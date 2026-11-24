"""Проверки провижиненных правил алертов Grafana.

Каждая проверка привязана к реальному дефекту, который уже стоил дежурства
(или который статистически ломает мониторинг). Коды — стабильные: на них
можно ссылаться в `# noqa`-комментариях и в CI.

GAL001  error    noDataState=Alerting при фильтрующем PromQL: пустая серия на
                 здоровом сервисе читается как авария, правило висит в Firing
GAL002  warning  noDataState=NoData: плановый разрыв метрик выглядит как авария
GAL003  error    noDataState отсутствует или неизвестен
GAL004  warning  нет `for` — правило срабатывает на первом промахе
GAL005  error    `<` или `>` в тексте аннотации: Grafana шлёт в Telegram с
                 parse_mode=HTML, Telegram отвечает 400, сообщение теряется
GAL006  error    `condition` ссылается на refId, которого нет в `data`
GAL007  error    повторяющийся `uid` правила — провижининг молча перезапишет
GAL008  warning  нет `labels.severity` — алерт не маршрутизируется по важности
GAL009  warning  нет `annotations.summary` — сообщение без сути
GAL010  warning  нет `execErrState` — ошибка вычисления обрабатывается молча
GAL011  warning  `for` короче интервала группы — дебаунс меньше шага оценки
GAL012  error    у правила нет ни `uid`, ни `title` — его нельзя ни найти, ни замьютить
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

LEVEL_ERROR = "error"
LEVEL_WARNING = "warning"

VALID_NO_DATA_STATES = {"OK", "Alerting", "NoData", "Error"}
VALID_EXEC_ERR_STATES = {"OK", "Alerting", "Error"}

# Фильтрующее сравнение в PromQL: результат — подмножество серий, а не все.
FILTERING_EXPR = re.compile(r"(==|!=)\s*-?\d")
# Символы, ломающие HTML-разметку исходящего сообщения.
HTML_UNSAFE = re.compile(r"[<>]")
# Модели вычислений Grafana: у них поле `expression`, а не PromQL.
EXPR_MODEL_TYPES = {"threshold", "math", "reduce", "resample"}

DURATION_PART = re.compile(r"(\d+)(ms|s|m|h|d)")
DURATION_UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}


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


def parse_duration(value: Any) -> float | None:
    """Grafana-длительность (`30s`, `1m`, `1h30m`) в секунды."""
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
        total += int(match.group(1)) * DURATION_UNITS[match.group(2)]
        pos = match.end()
        found = True
    if not found or pos != len(value):
        return None
    return total


def query_expressions(rule: dict[str, Any]) -> list[str]:
    """PromQL всех запросов правила, без служебных моделей вычислений."""
    out: list[str] = []
    for item in rule.get("data") or []:
        if not isinstance(item, dict):
            continue
        model = item.get("model") or {}
        if not isinstance(model, dict):
            continue
        if model.get("type") in EXPR_MODEL_TYPES:
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

    no_data = rule.get("noDataState")
    expressions = query_expressions(rule)
    filtering = [expr for expr in expressions if FILTERING_EXPR.search(expr)]

    if no_data is None:
        add("GAL003", LEVEL_ERROR, "noDataState не задан: поведение по умолчанию зависит от версии Grafana")
    elif no_data not in VALID_NO_DATA_STATES:
        add("GAL003", LEVEL_ERROR, f"noDataState={no_data!r} — допустимо {sorted(VALID_NO_DATA_STATES)}")
    elif no_data == "Alerting" and filtering:
        add(
            "GAL001",
            LEVEL_ERROR,
            "noDataState=Alerting при фильтрующем выражении "
            f"{filtering[0]!r}: на здоровом сервисе серия пуста, правило "
            "застрянет в Firing и никогда не закроется",
        )
    elif no_data == "NoData":
        add(
            "GAL002",
            LEVEL_WARNING,
            "noDataState=NoData: плановый разрыв метрик (сон, обслуживание) "
            "будет выглядеть как авария",
        )

    if not rule.get("for"):
        add("GAL004", LEVEL_WARNING, "нет for — срабатывание на первом же промахе")

    for key, value in rule_annotations(rule):
        if HTML_UNSAFE.search(value):
            add(
                "GAL005",
                LEVEL_ERROR,
                f"'<' или '>' в annotations.{key}: Telegram отвечает 400 на "
                "parse_mode=HTML, сообщение теряется молча",
            )

    ref_ids = {
        item.get("refId")
        for item in (rule.get("data") or [])
        if isinstance(item, dict) and item.get("refId")
    }
    condition = rule.get("condition")
    if condition and ref_ids and condition not in ref_ids:
        add("GAL006", LEVEL_ERROR, f"condition={condition!r} ссылается на отсутствующий refId {sorted(ref_ids)}")
    elif not condition:
        add("GAL006", LEVEL_ERROR, "condition не задан — правило не знает, что оценивать")

    labels = rule.get("labels") or {}
    if not isinstance(labels, dict) or not labels.get("severity"):
        add("GAL008", LEVEL_WARNING, "нет labels.severity — нечем маршрутизировать уведомления")

    annotations = rule.get("annotations") or {}
    if not isinstance(annotations, dict) or not annotations.get("summary"):
        add("GAL009", LEVEL_WARNING, "нет annotations.summary — в сообщении не будет сути")

    if rule.get("execErrState") is None:
        add("GAL010", LEVEL_WARNING, "нет execErrState — ошибка вычисления обработается по умолчанию")
    elif rule.get("execErrState") not in VALID_EXEC_ERR_STATES:
        add(
            "GAL010",
            LEVEL_WARNING,
            f"execErrState={rule.get('execErrState')!r} — допустимо {sorted(VALID_EXEC_ERR_STATES)}",
        )

    if group_interval is not None:
        rule_for = parse_duration(rule.get("for"))
        if rule_for is not None and rule_for < group_interval:
            add(
                "GAL011",
                LEVEL_WARNING,
                f"for={rule.get('for')!r} короче интервала группы "
                f"({group_interval:g}s) — дебаунс не длиннее шага оценки",
            )

    if not rule.get("uid") and not rule.get("title"):
        add("GAL012", LEVEL_ERROR, "нет ни uid, ни title — правило нельзя найти или замьютить")

    return findings


def lint_document(doc: Any, path: str = "<memory>") -> list[Finding]:
    """Проверяет один YAML-документ с группами правил."""
    if not isinstance(doc, dict):
        return []
    findings: list[Finding] = []
    seen_uids: dict[str, str] = {}
    seen_titles: dict[tuple[str, str], str] = {}

    for group in doc.get("groups") or []:
        if not isinstance(group, dict):
            continue
        group_name = str(group.get("name") or "?")
        interval = parse_duration(group.get("interval")) if group.get("interval") else None
        for index, rule in enumerate(group.get("rules") or []):
            if not isinstance(rule, dict):
                continue
            name = _label(rule, index)
            uid = rule.get("uid")
            if uid:
                if uid in seen_uids:
                    findings.append(
                        Finding(
                            "GAL007",
                            LEVEL_ERROR,
                            path,
                            group_name,
                            name,
                            f"uid={uid!r} уже занят правилом {seen_uids[uid]!r} — "
                            "провижининг перезапишет одно из них",
                        )
                    )
                else:
                    seen_uids[str(uid)] = name
            key = (group_name, name)
            if key in seen_titles:
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
                seen_titles[key] = name
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
    """Файл не читается или не разбирается как YAML."""


def lint_path(path: Path) -> list[Finding]:
    """Проверяет один файл (в нём может быть несколько YAML-документов)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LintError(f"{path}: не читается: {exc}") from exc
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise LintError(f"{path}: YAML не разбирается: {exc}") from exc
    findings: list[Finding] = []
    for doc in documents:
        findings.extend(lint_document(doc, str(path)))
    return findings
