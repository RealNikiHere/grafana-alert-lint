"""Проверки провижиненных правил алертов Grafana.

Каждая проверка привязана к реальному дефекту, который уже стоил дежурства
(или который статистически ломает мониторинг). Коды — стабильные: на них
можно ссылаться в CI и в обсуждениях.

GAL001  error    сравнение в PromQL при `noDataState: Alerting`: на здоровом
                 сервисе серия отфильтрована, результат пуст, правило висит
                 в Firing и не закрывается
GAL002  warning  noDataState=NoData: плановый разрыв метрик выглядит как авария
GAL003  error    noDataState отсутствует или неизвестен
GAL004  warning  нет `for` — правило срабатывает на первом промахе
GAL005  error    `<` в тексте аннотации: Grafana шлёт в Telegram с
                 parse_mode=HTML, Telegram отвечает 400, сообщение теряется
GAL006  error    `condition` не задан, ссылается на отсутствующий refId или
                 `data` пуст
GAL007  error    повторяющийся `uid` или `title` — провижининг молча
                 перезапишет одно правило другим
GAL008  warning  нет `labels.severity` — алерт не маршрутизируется по важности
GAL009  warning  нет `annotations.summary` — сообщение без сути
GAL010  warning  нет `execErrState` или значение неизвестно
GAL011  warning  `for` короче интервала группы — дебаунс меньше шага оценки
GAL012  error    у правила нет ни `uid`, ни `title` — его нельзя ни найти, ни замьютить
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

LEVEL_ERROR = "error"
LEVEL_WARNING = "warning"

# Значения, которые принимает Grafana (KeepLast — «оставить прошлое состояние»).
VALID_NO_DATA_STATES = {"OK", "Alerting", "NoData", "KeepLast"}
VALID_EXEC_ERR_STATES = {"OK", "Alerting", "Error", "KeepLast"}

# Grafana оценивает правило раз в минуту, если интервал группы не задан.
DEFAULT_GROUP_INTERVAL_SECONDS = 60.0

# Разбор YAML амплифицирует память примерно в 70-80 раз к размеру файла:
# 30 МВ файла — это >2 ГБ RSS. Реальные провижининги — килобайты, поэтому
# по умолчанию отказываемся от файлов больше 32 МВ с понятной ошибкой.
DEFAULT_MAX_FILE_BYTES = 32 * 1024 * 1024

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

DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)(ms|s|m|h|d|w|y)")
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

    Grafana требует глобальной уникальности `uid` правил: два файла с одним
    `uid` перезапишут друг друга молча. Поэтому состояние передаётся между
    документами и файлами.

    Контракт: состояние только накапливается и не очищается. Повторный вызов
    `lint_document` с тем же объектом на тех же данных даст ложные GAL007 —
    для нового независимого прогона создавайте новый `LintState` (CLI так и
    делает, по одному на запуск).
    """

    uids: dict[str, str] = field(default_factory=dict)
    titles: dict[tuple[str, str], str] = field(default_factory=dict)


def parse_duration(value: Any) -> float | None:
    """Grafana-длительность (`30s`, `1m`, `1h30m`, `1.5s`) в секунды."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return None
    pos = 0
    total = 0.0
    found = False
    for match in DURATION_PART.finditer(value):
        if match.start() != pos:
            return None
        total += float(match.group(1)) * DURATION_UNITS[match.group(2)]
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
        if isinstance(datasource, dict) and datasource.get("uid") == "__expr__":
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


def _label(rule: dict[str, Any], index: int) -> str:
    return str(rule.get("title") or rule.get("uid") or f"rule[{index}]")


def lint_rule(
    rule: dict[str, Any],
    *,
    path: str,
    group: str,
    index: int,
    group_interval: float | None,
) -> list[Finding]:
    """Проверяет одно правило и возвращает найденные проблемы."""
    name = _label(rule, index)
    findings: list[Finding] = []

    def add(code: str, level: str, message: str) -> None:
        findings.append(Finding(code, level, path, group, name, message))

    raw_no_data = rule.get("noDataState")
    no_data = as_scalar_str(raw_no_data)
    expressions = query_expressions(rule)
    filtering = [expr for expr in expressions if is_filtering_expression(expr)]

    if raw_no_data is None:
        add("GAL003", LEVEL_ERROR, "noDataState не задан: поведение по умолчанию зависит от версии Grafana")
    elif no_data is None:
        add("GAL003", LEVEL_ERROR, f"noDataState={raw_no_data!r} — не строка и не число, Grafana его не примет")
    elif no_data not in VALID_NO_DATA_STATES:
        add("GAL003", LEVEL_ERROR, f"noDataState={no_data!r} — допустимо {sorted(VALID_NO_DATA_STATES)}")
    elif no_data == "Alerting" and filtering:
        add(
            "GAL001",
            LEVEL_ERROR,
            "noDataState=Alerting при фильтрующем выражении "
            f"{filtering[0]!r}: сравнение отбрасывает серии, поэтому на "
            "здоровом состоянии результат пуст (или серия остаётся только при "
            "аварии) — правило не закрывается само; проверьте порог живьём",
        )
    elif no_data == "NoData":
        add(
            "GAL002",
            LEVEL_WARNING,
            "noDataState=NoData: плановый разрыв метрик (сон, обслуживание) "
            "будет выглядеть как авария",
        )

    raw_for = rule.get("for")
    for_is_duration = parse_duration(raw_for) is not None or (
        raw_for == 0 and not isinstance(raw_for, bool)
    )
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
        add("GAL006", LEVEL_ERROR, f"condition={raw_condition!r} — не строка, Grafana его не примет")
    elif not ref_ids:
        add("GAL006", LEVEL_ERROR, "condition задан, но в data нет ни одного refId — оценивать нечего")
    elif condition not in ref_ids:
        add("GAL006", LEVEL_ERROR, f"condition={condition!r} ссылается на отсутствующий refId {sorted(ref_ids)}")

    labels = rule.get("labels") or {}
    if not isinstance(labels, dict) or not as_scalar_str(labels.get("severity")):
        add("GAL008", LEVEL_WARNING, "нет labels.severity — нечем маршрутизировать уведомления")

    annotations = rule.get("annotations") or {}
    if not isinstance(annotations, dict) or not as_scalar_str(annotations.get("summary")):
        add("GAL009", LEVEL_WARNING, "нет annotations.summary — в сообщении не будет сути")

    raw_exec_err = rule.get("execErrState")
    exec_err = as_scalar_str(raw_exec_err)
    if raw_exec_err is None:
        add("GAL010", LEVEL_WARNING, "нет execErrState — ошибка вычисления обработается по умолчанию")
    elif exec_err is None:
        add("GAL010", LEVEL_WARNING, f"execErrState={raw_exec_err!r} — не строка, Grafana его не примет")
    elif exec_err not in VALID_EXEC_ERR_STATES:
        add("GAL010", LEVEL_WARNING, f"execErrState={exec_err!r} — допустимо {sorted(VALID_EXEC_ERR_STATES)}")

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

    return findings


def lint_document(
    doc: Any,
    path: str = "<memory>",
    *,
    state: LintState | None = None,
) -> list[Finding]:
    """Проверяет один YAML-документ с группами правил."""
    if not isinstance(doc, dict):
        return []
    state = state if state is not None else LintState()
    findings: list[Finding] = []

    for group in as_list(doc.get("groups")):
        if not isinstance(group, dict):
            continue
        group_name = str(group.get("name") or "?")
        interval = parse_duration(group.get("interval"))
        if interval is None:
            interval = DEFAULT_GROUP_INTERVAL_SECONDS
        for index, rule in enumerate(as_list(group.get("rules"))):
            if not isinstance(rule, dict):
                continue
            name = _label(rule, index)
            uid_key = as_scalar_str(rule.get("uid"))
            if uid_key not in (None, ""):
                key = uid_key
                if key in state.uids:
                    findings.append(
                        Finding(
                            "GAL007",
                            LEVEL_ERROR,
                            path,
                            group_name,
                            name,
                            f"uid={key!r} уже занят правилом {state.uids[key]!r} — "
                            "провижининг перезапишет одно из них",
                        )
                    )
                else:
                    state.uids[key] = name
            # `title` — своё поле: uid одного правила не должен считаться
            # дублем title другого.
            title_value = as_scalar_str(rule.get("title"))
            title_key = (group_name, title_value or "")
            if title_value in (None, ""):
                pass
            elif title_key in state.titles:
                findings.append(
                    Finding(
                        "GAL007",
                        LEVEL_ERROR,
                        path,
                        group_name,
                        name,
                        "правило с таким title уже есть в группе — различать их будет нечем",
                    )
                )
            else:
                state.titles[title_key] = name
            findings.extend(
                lint_rule(
                    rule,
                    path=path,
                    group=group_name,
                    index=index,
                    group_interval=interval,
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
) -> list[Finding]:
    """Проверяет один файл (в нём может быть несколько YAML-документов).

    Состояние уникальности (`uid`, `title`) по умолчанию своё на файл; чтобы
    ловить дубли между файлами, передайте общий `LintState`.

    `max_bytes` ограничивает размер файла (по умолчанию 32 МВ): разбор YAML
    раздувает память на порядок, и файл на сотни мегабайт — это OOM, а не
    линт. `None` или `0` — без ограничения.
    """
    if max_bytes:
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise LintError(f"{path}: не читается: {exc}") from exc
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
            findings.extend(lint_document(doc, str(path), state=state))
    except (yaml.YAMLError, RecursionError) as exc:
        raise LintError(f"{path}: YAML не разбирается: {exc}", findings) from exc
    return findings
