"""Проверки провижиненных правил алертов Grafana.

Каждая проверка привязана к реальному дефекту, который уже стоил дежурства
(или который статистически ломает мониторинг). Коды — стабильные: на них
можно ссылаться в CI и в обсуждениях.

GAL001  error    сравнение в PromQL при `noDataState: Alerting`: на здоровом
                 сервисе серия отфильтрована, результат пуст, правило висит
                 в Firing и не закрывается
GAL002  warning  noDataState=NoData: плановый разрыв метрик выглядит как авария
GAL003  error    noDataState отсутствует или неизвестен (Grafana принимает
                 OK, Alerting, NoData, KeepLast; Error — только для execErrState)
GAL004  warning  нет `for`, или значение не длительность Grafana —
                 правило срабатывает на первом промахе
GAL005  error    `<` в тексте аннотации: Grafana шлёт в Telegram с
                 parse_mode=HTML, Telegram отвечает 400, сообщение теряется
GAL006  error    `condition` не задан, ссылается на отсутствующий refId или
                 `data` пуст
GAL007  error    повторяющийся `uid` в пределах orgId — провижининг молча
                 перезапишет одно правило другим
GAL007  warning  повторяющийся `title` в пределах (orgId, folder): Grafana до
                 11.6 такое отвергает, с 11.6 разрешает, но правила сольются
                 в одну группу уведомлений
GAL008  warning  нет `labels.severity` — алерт не маршрутизируется по важности
GAL009  warning  нет `annotations.summary` — сообщение без сути
GAL010  warning  нет `execErrState` или значение неизвестно
GAL011  warning  `for` короче интервала группы — дебаунс меньше шага оценки
GAL012  error    у правила нет ни `uid`, ни `title` — его нельзя ни найти, ни замьютить
GAL013  error    `interval` группы не разбирается как длительность Grafana

GAL002, GAL004, GAL008, GAL009, GAL010 и GAL011 — вкусовые: они не про
поломку провижининга, а про качество алертинга, поэтому по умолчанию молчат и
включаются флагом `--opinionated` (см. `STYLE_CHECKS`).
"""

from __future__ import annotations

import re
import stat
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

LEVEL_ERROR = "error"
LEVEL_WARNING = "warning"

# Проверки про качество алертинга, а не про поломку провижининга: по умолчанию
# молчат, включаются `--opinionated`. Иначе чужой прогон получает десятки
# «нет severity» и не видит настоящей находки.
STYLE_CHECKS = frozenset({"GAL002", "GAL004", "GAL008", "GAL009", "GAL010", "GAL011"})

# Grafana нумерует организации с 1; в провижининге `orgId` можно не указывать.
DEFAULT_ORG_ID = "1"
DEFAULT_FOLDER = ""

# Значения, которые принимает Grafana (KeepLast — «оставить прошлое состояние»).
VALID_NO_DATA_STATES = {"OK", "Alerting", "NoData", "KeepLast"}
VALID_EXEC_ERR_STATES = {"OK", "Alerting", "Error", "KeepLast"}

# Grafana оценивает правило раз в минуту, если интервал группы не задан.
DEFAULT_GROUP_INTERVAL_SECONDS = 60.0

# Разбор YAML амплифицирует память примерно в 70-80 раз к размеру файла:
# 30 МВ файла — это >2 ГБ RSS. Реальные провижининги — килобайты, поэтому
# по умолчанию отказываемся от файлов больше 4 МиБ (это уже ~300 МБ памяти).
DEFAULT_MAX_FILE_BYTES = 4 * 1024 * 1024

# Модели вычислений Grafana: у них поле `expression`, а не PromQL.
EXPR_MODEL_TYPES = {"threshold", "math", "reduce", "resample"}

# Строковые литералы и матчеры лейблов: их содержимое — не выражения.
STRING_LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|`[^`]*`')
LABEL_MATCHERS = re.compile(r"\{[^}]*\}")
# Сравнение вне `bool`-модификатора отбрасывает серии: именно это и создаёт
# пустой результат на здоровом сервисе.
COMPARISON = re.compile(r"(==|!=|>=|<=|>|<)\s*(bool\b)?")
# `<` начинает HTML-тег; `>` в тексте Telegram безвреден.
INVALID_HTML = re.compile(r"<")

DURATION_PART = re.compile(r"(\d+)(ms|s|m|h|d|w|y)")
DURATION_UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "y": 31536000}


@dataclass(frozen=True)
class Finding:
    """Одна проблема в одном правиле."""

    code: str
    level: str
    path: str
    group: str
    rule: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "level": self.level,
            "path": self.path,
            "group": self.group,
            "rule": self.rule,
            "message": self.message,
        }

    def __str__(self) -> str:
        where = f"{self.path}:{self.group}/{self.rule}"
        return f"{where}: {self.level} {self.code} {self.message}"


@dataclass
class LintState:
    """То, что должно быть уникально на весь провижининг, а не на один файл.

    Границы уникальности в Grafana: `uid` — в пределах организации, `title` —
    в пределах (организация, папка). Поэтому ключи включают `orgId` и `folder`:
    одинаковый `uid` в `orgId: 1` и `orgId: 2` легален, а одинаковый `title`
    правила в разных папках — разные правила.

    Контракт: состояние только накапливается и не очищается. Повторный вызов
    `lint_document` с тем же объектом на тех же данных даст ложные GAL007 —
    для нового независимого прогона создавайте новый `LintState` (CLI так и
    делает, по одному на запуск).
    """

    uids: dict[tuple[str, str], str] = field(default_factory=dict)
    titles: dict[tuple[str, str, str], str] = field(default_factory=dict)


def parse_duration(value: Any) -> float | None:
    """Grafana-длительность (`30s`, `1m`, `1h30m`) в секунды.

    Grafana разбирает длительности `model.ParseDuration`: только целые части,
    без дробей (`1.5s` она отвергает). Огромные числа дают бесконечность или
    `OverflowError` — такое значение тоже не длительность.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            seconds = float(value)
        except OverflowError:
            return None
        return seconds if seconds >= 0 else None
    if not isinstance(value, str):
        return None
    pos = 0
    total = 0.0
    found = False
    for match in DURATION_PART.finditer(value):
        if match.start() != pos:
            return None
        try:
            total += int(match.group(1)) * DURATION_UNITS[match.group(2)]
        except (OverflowError, ValueError):
            return None
        pos = match.end()
        found = True
    if not found or pos != len(value):
        return None
    return total


def is_filtering_expression(expr: str) -> bool:
    """Отбрасывает ли выражение серии сравнением.

    `up == 0` при `up=1` отбрасывает единственную серию → пустой результат.
    Матчеры лейблов (`{version="1 == 0"}`) и строки — не сравнения; сравнение
    с модификатором `bool` возвращает 0/1 для всех серий и ничего не фильтрует.
    """
    cleaned = LABEL_MATCHERS.sub("{}", STRING_LITERAL.sub('""', expr))
    for match in COMPARISON.finditer(cleaned):
        if match.group(2) is None:
            return True
    return False


def as_list(value: Any) -> list[Any]:
    """Список или пустой список: скаляр в позиции списка встречается в
    поломанном провижининге и не должен ронять линтер трейсбеком."""
    return value if isinstance(value, list) else []


def as_scalar_str(value: Any) -> str | None:
    """Скаляр YAML → строка; словарь/список (невалидные для этих полей) → None.

    Grafana-поля вроде `noDataState` или `refId` — строки. Значение-словарь в
    этом месте означает поломанный провижининг, но линтер не должен падать
    на `unhashable type: 'dict'`: такое поле считается незаданным.
    """
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return None


def query_expressions(rule: dict[str, Any]) -> list[str]:
    """PromQL всех запросов правила, без служебных моделей вычислений."""
    out: list[str] = []
    for item in as_list(rule.get("data")):
        if not isinstance(item, dict):
            continue
        model = item.get("model") or {}
        if not isinstance(model, dict):
            continue
        if as_scalar_str(model.get("type")) in EXPR_MODEL_TYPES:
            continue
        datasource = model.get("datasource") or {}
        # `datasource` бывает словарём, но встречается и строкой uid; плюс
        # отдельное поле `datasourceUid` на уровне запроса.
        if isinstance(datasource, dict) and datasource.get("uid") == "__expr__":
            continue
        if as_scalar_str(datasource) == "__expr__":
            continue
        if as_scalar_str(item.get("datasourceUid")) == "__expr__":
            continue
        for key in ("expr", "expression"):
            expr = model.get(key)
            if isinstance(expr, str) and expr and not expr.startswith("$"):
                out.append(expr)
    return out


def rule_annotations(rule: dict[str, Any]) -> Iterable[tuple[str, str]]:
    annotations = rule.get("annotations") or {}
    if not isinstance(annotations, dict):
        return
    for key, value in annotations.items():
        if isinstance(value, str):
            yield str(key), value


def _non_blank(value: Any) -> str | None:
    """Скаляр, в котором есть хоть один непробельный символ, иначе None."""
    scalar = as_scalar_str(value)
    if scalar is None or not scalar.strip():
        return None
    return scalar


def _org_key(value: Any) -> str:
    """`orgId` в сравнимый вид: `1`, `1.0` и `"1"` — одна организация."""
    if value is None or isinstance(value, bool):
        return DEFAULT_ORG_ID
    if isinstance(value, float):
        if not value.is_integer():
            return str(value)
        return str(int(value))
    return as_scalar_str(value) or DEFAULT_ORG_ID


def _label(rule: dict[str, Any], index: int) -> str:
    return str(rule.get("title") or rule.get("uid") or f"rule[{index}]")


def lint_rule(
    rule: dict[str, Any],
    *,
    path: str,
    group: str,
    index: int,
    group_interval: float | None,
    opinionated: bool = False,
) -> list[Finding]:
    """Проверяет одно правило и возвращает найденные проблемы.

    `opinionated` включает вкусовые проверки из `STYLE_CHECKS`.
    """
    name = _label(rule, index)
    findings: list[Finding] = []

    def add(code: str, level: str, message: str) -> None:
        findings.append(Finding(code, level, path, group, name, message))

    raw_no_data = rule.get("noDataState")
    no_data = as_scalar_str(raw_no_data)
    expressions = query_expressions(rule)
    filtering = [expr for expr in expressions if is_filtering_expression(expr)]

    if raw_no_data is None:
        add(
            "GAL003",
            LEVEL_ERROR,
            "noDataState не задан: поведение по умолчанию зависит от версии Grafana",
        )
    elif no_data is None:
        add(
            "GAL003",
            LEVEL_ERROR,
            f"noDataState={raw_no_data!r} — не строка и не число, Grafana его не примет",
        )
    elif no_data not in VALID_NO_DATA_STATES:
        add(
            "GAL003",
            LEVEL_ERROR,
            f"noDataState={no_data!r} — допустимо {sorted(VALID_NO_DATA_STATES)}",
        )
    elif no_data == "Alerting" and filtering:
        add(
            "GAL001",
            LEVEL_ERROR,
            "noDataState=Alerting при сравнении в PromQL "
            f"{filtering[0]!r}: Grafana считает пустой результат тревогой, а "
            "сравнение как раз создаёт пустоту, когда условие не выполнено, — "
            "такое правило не закрывается само. Если это осознанный алерт на "
            "отсутствие данных, используйте --ignore GAL001",
        )
    elif no_data == "NoData":
        add(
            "GAL002",
            LEVEL_WARNING,
            "noDataState=NoData: плановый разрыв метрик (сон, обслуживание) "
            "будет выглядеть как авария",
        )

    raw_for = rule.get("for")
    for_is_duration = parse_duration(raw_for) is not None
    if raw_for is None or raw_for == "":
        add("GAL004", LEVEL_WARNING, "нет for — срабатывание на первом же промахе")
    elif not for_is_duration:
        add("GAL004", LEVEL_WARNING, f"for={raw_for!r} — не длительность и не число секунд")

    for key, value in rule_annotations(rule):
        if INVALID_HTML.search(value):
            add(
                "GAL005",
                LEVEL_ERROR,
                f"'<' в annotations.{key}: Grafana шлёт с parse_mode=HTML, "
                "Telegram отвечает 400 и сообщение теряется молча",
            )

    ref_ids = {
        ref
        for item in as_list(rule.get("data"))
        if isinstance(item, dict)
        for ref in [as_scalar_str(item.get("refId"))]
        if ref
    }
    raw_condition = rule.get("condition")
    condition = as_scalar_str(raw_condition)
    if raw_condition is None:
        add("GAL006", LEVEL_ERROR, "condition не задан — правило не знает, что оценивать")
    elif condition is None:
        add(
            "GAL006", LEVEL_ERROR, f"condition={raw_condition!r} — не строка, Grafana его не примет"
        )
    elif not ref_ids:
        add(
            "GAL006",
            LEVEL_ERROR,
            "condition задан, но в data нет ни одного refId — оценивать нечего",
        )
    elif condition not in ref_ids:
        add(
            "GAL006",
            LEVEL_ERROR,
            f"condition={condition!r} ссылается на отсутствующий refId {sorted(ref_ids)}",
        )

    labels = rule.get("labels") or {}
    if not isinstance(labels, dict) or not _non_blank(labels.get("severity")):
        add("GAL008", LEVEL_WARNING, "нет labels.severity — нечем маршрутизировать уведомления")

    annotations = rule.get("annotations") or {}
    if not isinstance(annotations, dict) or not _non_blank(annotations.get("summary")):
        add("GAL009", LEVEL_WARNING, "нет annotations.summary — в сообщении не будет сути")

    raw_exec_err = rule.get("execErrState")
    exec_err = as_scalar_str(raw_exec_err)
    if raw_exec_err is None:
        add(
            "GAL010",
            LEVEL_WARNING,
            "нет execErrState — ошибка вычисления обработается по умолчанию",
        )
    elif exec_err is None:
        add(
            "GAL010",
            LEVEL_WARNING,
            f"execErrState={raw_exec_err!r} — не строка, Grafana его не примет",
        )
    elif exec_err not in VALID_EXEC_ERR_STATES:
        add(
            "GAL010",
            LEVEL_WARNING,
            f"execErrState={exec_err!r} — допустимо {sorted(VALID_EXEC_ERR_STATES)}",
        )

    rule_for = parse_duration(rule.get("for"))
    if group_interval is not None and rule_for is not None and 0 < rule_for < group_interval:
        add(
            "GAL011",
            LEVEL_WARNING,
            f"for={rule.get('for')!r} короче интервала группы "
            f"({group_interval:g}s) — дебаунс не длиннее шага оценки",
        )

    has_uid = as_scalar_str(rule.get("uid")) not in (None, "")
    has_title = as_scalar_str(rule.get("title")) not in (None, "")
    if not has_uid and not has_title:
        add("GAL012", LEVEL_ERROR, "нет ни uid, ни title — правило нельзя найти или замьютить")

    if not opinionated:
        findings = [finding for finding in findings if finding.code not in STYLE_CHECKS]
    return findings


def lint_document(
    doc: Any,
    path: str = "<memory>",
    *,
    state: LintState | None = None,
    opinionated: bool = False,
) -> list[Finding]:
    """Проверяет один YAML-документ с группами правил.

    `opinionated` включает вкусовые проверки из `STYLE_CHECKS`.
    """
    if not isinstance(doc, dict):
        return []
    state = state if state is not None else LintState()
    findings: list[Finding] = []

    for group in as_list(doc.get("groups")):
        if not isinstance(group, dict):
            continue
        group_name = str(group.get("name") or "?")
        org_id = _org_key(group.get("orgId"))
        folder = as_scalar_str(group.get("folder")) or DEFAULT_FOLDER
        raw_interval = group.get("interval")
        if raw_interval == "":
            raw_interval = None
        interval = parse_duration(raw_interval)
        if raw_interval is None:
            # Grafana подставляет свой интервал группы; для сравнения с `for`
            # берём её дефолт — минуту.
            interval = DEFAULT_GROUP_INTERVAL_SECONDS
        elif interval is None:
            findings.append(
                Finding(
                    "GAL013",
                    LEVEL_ERROR,
                    path,
                    group_name,
                    "(группа)",
                    f"interval={raw_interval!r} не разбирается как длительность "
                    "Grafana (например 30s, 1m, 1h30m) — правило будет "
                    "оцениваться не так, как задумано",
                )
            )
            interval = None  # 60 с на место битого значения — враньё в GAL011
        elif interval <= 0:
            findings.append(
                Finding(
                    "GAL013",
                    LEVEL_ERROR,
                    path,
                    group_name,
                    "(группа)",
                    f"interval={raw_interval!r} — Grafana требует больше нуля",
                )
            )
            interval = None
        for index, rule in enumerate(as_list(group.get("rules"))):
            if not isinstance(rule, dict):
                continue
            name = _label(rule, index)
            uid_key = as_scalar_str(rule.get("uid"))
            if uid_key not in (None, ""):
                key = (org_id, uid_key)
                if key in state.uids:
                    findings.append(
                        Finding(
                            "GAL007",
                            LEVEL_ERROR,
                            path,
                            group_name,
                            name,
                            f"uid={uid_key!r} уже занят правилом {state.uids[key]!r} "
                            f"(orgId={org_id}) — провижининг перезапишет одно из них",
                        )
                    )
                else:
                    state.uids[key] = name
            # `title` — своё поле: uid одного правила не должен считаться
            # дублем title другого. Регистрируется и для recording rules: их
            # title тоже занимает имя в папке.
            title_value = as_scalar_str(rule.get("title"))
            title_key = (org_id, folder, title_value or "")
            if title_value in (None, ""):
                pass
            elif title_key in state.titles:
                findings.append(
                    Finding(
                        "GAL007",
                        LEVEL_WARNING,
                        path,
                        group_name,
                        name,
                        "правило с таким title уже есть в этой папке "
                        f"(orgId={org_id}, folder={folder or '—'}) — до Grafana 11.6 "
                        "провижининг его отвергнет, с 11.6 разрешит, но правила "
                        "попадут в одну группу уведомлений",
                    )
                )
            else:
                state.titles[title_key] = name
            if isinstance(rule.get("record"), dict):
                # Grafana-managed recording rule: нет condition/noDataState и не
                # должно быть — проверки алертов к нему неприменимы.
                continue
            findings.extend(
                lint_rule(
                    rule,
                    path=path,
                    group=group_name,
                    index=index,
                    group_interval=interval,
                    opinionated=opinionated,
                )
            )
    return findings


class LintError(Exception):
    """Файл не читается или не разбирается как YAML.

    `findings` — то, что успели найти в уже разобранных документах файла:
    ошибка в третьем документе не должна отменять находки из первых двух.
    """

    def __init__(self, message: str, findings: list[Finding] | None = None) -> None:
        super().__init__(message)
        self.findings: list[Finding] = findings or []


def lint_path(
    path: Path,
    *,
    state: LintState | None = None,
    max_bytes: int | None = DEFAULT_MAX_FILE_BYTES,
    opinionated: bool = False,
) -> list[Finding]:
    """Проверяет один файл (в нём может быть несколько YAML-документов).

    Состояние уникальности (`uid`, `title`) по умолчанию своё на файл; чтобы
    ловить дубли между файлами, передайте общий `LintState`.

    `max_bytes` ограничивает размер файла (по умолчанию 4 МиБ): разбор YAML
    раздувает память примерно в 70-80 раз, и файл в десятки мегабайт — это
    OOM, а не линт. `None` или `0` — без ограничения.
    """
    try:
        stat_result = path.stat()
    except OSError as exc:
        raise LintError(f"{path}: не читается: {exc}") from exc
    if not stat.S_ISREG(stat_result.st_mode):
        # FIFO и символьные устройства не заканчиваются никогда: read_text на
        # /dev/zero или на канале без писателя висит навсегда.
        raise LintError(f"{path}: не обычный файл (FIFO, устройство или каталог) — не читаю")
    if max_bytes:
        size = stat_result.st_size
        if size > max_bytes:
            raise LintError(
                f"{path}: файл {size} байт больше лимита {max_bytes} — "
                "поднимите его флагом --max-file-size (0 — без лимита)"
            )
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise LintError(f"{path}: не читается: {exc}") from exc
    state = state if state is not None else LintState()
    findings: list[Finding] = []
    try:
        # Документы читаются по одному: файл на десятки мегабайт не обязан
        # целиком лежать в памяти как список, а глубоко вложенный YAML даёт
        # RecursionError, а не YAMLError.
        for doc in yaml.safe_load_all(text):
            findings.extend(lint_document(doc, str(path), state=state, opinionated=opinionated))
    except (yaml.YAMLError, RecursionError) as exc:
        raise LintError(f"{path}: YAML не разбирается: {exc}", findings) from exc
    return findings
