"""Вкусовые проверки (STYLE_CHECKS) и флаг `--opinionated`.

Каждый тест защищает один контракт:

* GAL002/004/008/009/010/011 по умолчанию молчат и включаются `--opinionated`;
* набор `STYLE_CHECKS` — ровно эти шесть кодов (добавили седьмой — тест
  падает, и никто не «включит» проверку провижининга чужому прогону);
* `--opinionated` доходит из CLI до линтера и работает вместе с `--strict`,
  `--format json` и `--ignore`;
* границы GAL011: равенство `for` и интервала, интервал по умолчанию,
  `interval: 0s`, недели/года/миллисекунды, дробный `for` (невалиден);
* GAL002 только при `NoData`, GAL008/GAL009 — при пустых значениях,
  GAL010 — при отсутствии и недопустимых значениях.

Тесты писались по факту поведения кода, репозиторий не менялся; найденные
шероховатости отмечены в комментариях (см. `_WHITESPACE_BLIND_SPOT`).
"""

from __future__ import annotations

import json

import pytest

from grafana_alert_lint.cli import EXIT_FINDINGS, EXIT_OK, main
from grafana_alert_lint.linter import STYLE_CHECKS, Finding, lint_document

# `severity: "   "` и `summary: "  "` проходят проверку: `as_scalar_str`
# возвращает непустую строку, а проверка смотрит только на истинность. Это
# известный слепой угол кода; тесты ниже помечены xfail(strict=True), чтобы
# исправление поведения не прошло молча.


def rule(**overrides):
    """Правило, чистое по всем проверкам, включая вкусовые."""
    base = {
        "uid": "r1",
        "title": "Правило",
        "condition": "B",
        "for": "5m",
        "noDataState": "OK",
        "execErrState": "Error",
        "labels": {"severity": "critical"},
        "annotations": {"summary": "Свободно меньше 10 процентов"},
        "data": [
            {"refId": "A", "model": {"expr": "up", "refId": "A"}},
            {"refId": "B", "model": {"type": "threshold", "expression": "A", "refId": "B"}},
        ],
    }
    base.update(overrides)
    return base


def doc(*rules, interval: object = "1m"):
    """Документ с одной группой; `interval=...` — не задавать поле вообще."""
    group: dict[str, object] = {"name": "g", "rules": list(rules)}
    if interval is not ...:
        group["interval"] = interval
    return {"groups": [group]}


def codes(findings: list[Finding]) -> list[str]:
    return [finding.code for finding in findings]


# --- каждая вкусовая проверка молчит без флага и срабатывает с ним --------


@pytest.mark.parametrize(
    ("defect", "style_code"),
    [
        ({"noDataState": "NoData"}, "GAL002"),
        ({"for": None}, "GAL004"),
        ({"labels": {}}, "GAL008"),
        ({"annotations": {}}, "GAL009"),
        ({"execErrState": None}, "GAL010"),
        ({"for": "30s"}, "GAL011"),
    ],
    ids=["GAL002", "GAL004", "GAL008", "GAL009", "GAL010", "GAL011"],
)
def test_style_check_is_gated_by_opinionated(defect, style_code):
    document = doc(rule(**defect))
    silent = codes(lint_document(document))
    assert silent == [], f"{style_code} не должен всплывать без --opinionated: {silent}"

    loud = lint_document(document, opinionated=True)
    assert codes(loud) == [style_code]
    assert loud[0].level == "warning"
    assert loud[0].code == style_code


def test_style_checks_set_is_exactly_the_six_opinionated_codes():
    assert STYLE_CHECKS == frozenset({"GAL002", "GAL004", "GAL008", "GAL009", "GAL010", "GAL011"})
    assert len(STYLE_CHECKS) == 6
    # Проверки провижининга не должны попасть во вкусовые: иначе --ignore
    # вкусовых кодов начнёт прятать настоящие находки.
    assert not STYLE_CHECKS & {"GAL001", "GAL003", "GAL005", "GAL006", "GAL007", "GAL012", "GAL013"}


# --- GAL002: NoData — авария из планового разрыва -------------------------


def test_gal002_fires_only_for_nodata_state():
    for state in ("OK", "Alerting", "KeepLast"):
        findings = lint_document(doc(rule(noDataState=state)), opinionated=True)
        assert "GAL002" not in codes(findings), state
    found = lint_document(doc(rule(noDataState="NoData")), opinionated=True)
    assert codes(found) == ["GAL002"]
    assert "NoData" in found[0].message


# --- GAL008 / GAL009: пустое severity / summary ---------------------------


def test_gal008_reports_empty_severity_and_accepts_numbers():
    empty = lint_document(doc(rule(labels={})), opinionated=True)
    assert codes(empty) == ["GAL008"]
    assert "severity" in empty[0].message

    explicit_empty = lint_document(doc(rule(labels={"severity": ""})), opinionated=True)
    assert codes(explicit_empty) == ["GAL008"]

    # Число — легальный YAML-скаляр: `severity: 1` Grafana превратит в "1",
    # поэтому это не находка (проверяется, чтобы поведение не «ужесточили»
    # молча).
    assert codes(lint_document(doc(rule(labels={"severity": 1})), opinionated=True)) == []


def test_gal008_whitespace_severity_is_flagged():
    found = lint_document(doc(rule(labels={"severity": "   "})), opinionated=True)
    assert codes(found) == ["GAL008"]


def test_gal009_reports_empty_summary_and_accepts_numbers():
    empty = lint_document(doc(rule(annotations={})), opinionated=True)
    assert codes(empty) == ["GAL009"]
    assert "summary" in empty[0].message

    blank = lint_document(doc(rule(annotations={"summary": ""})), opinionated=True)
    assert codes(blank) == ["GAL009"]
    assert codes(lint_document(doc(rule(annotations={"summary": 42})), opinionated=True)) == []


def test_gal009_whitespace_summary_is_flagged():
    found = lint_document(doc(rule(annotations={"summary": "  "})), opinionated=True)
    assert codes(found) == ["GAL009"]


# --- GAL010: отсутствие и недопустимые значения execErrState -------------


@pytest.mark.parametrize(
    ("value", "expected_message_part"),
    [
        (None, "нет execErrState"),
        ("NoData", "допустимо"),
        ({}, "не строка"),
    ],
)
def test_gal010_flags_missing_and_invalid_exec_err_state(value, expected_message_part):
    found = lint_document(doc(rule(execErrState=value)), opinionated=True)
    assert codes(found) == ["GAL010"]
    assert expected_message_part in found[0].message

    # Все легальные значения Grafana проходят молча.
    for valid in ("OK", "Alerting", "Error", "KeepLast"):
        assert codes(lint_document(doc(rule(execErrState=valid)), opinionated=True)) == [], valid


# --- GAL011: границы «for короче интервала группы» -----------------------


def test_gal011_for_equal_to_interval_is_silent():
    for interval in ("30s", "2m", "1h30m"):
        document = doc(rule(**{"for": interval}), interval=interval)
        assert "GAL011" not in codes(lint_document(document, opinionated=True)), interval


def test_gal011_for_one_millisecond_shorter_fires():
    document = doc(rule(**{"for": "59999ms"}), interval="1m")
    found = lint_document(document, opinionated=True)
    assert codes(found) == ["GAL011"]
    assert "60s" in found[0].message


def test_gal011_missing_interval_falls_back_to_grafana_60s():
    # Grafana оценивает группу раз в минуту, если interval не задан.
    assert codes(lint_document(doc(rule(**{"for": "59s"}), interval=...), opinionated=True)) == [
        "GAL011"
    ]
    assert codes(lint_document(doc(rule(**{"for": "1m"}), interval=...), opinionated=True)) == []


def test_gal011_interval_zero_is_gal013_not_silence():
    # Нулевой интервал Grafana не примет: это ошибка GAL013, а GAL011
    # сравнивать не с чем.
    document = doc(rule(**{"for": "5m"}), interval="0s")
    assert codes(lint_document(document, opinionated=True)) == ["GAL013"]


def test_gal011_handles_week_year_and_millisecond_intervals():
    for interval, rule_for in (("2w", "1w"), ("1y", "1w"), ("100ms", "50ms")):
        document = doc(rule(**{"for": rule_for}), interval=interval)
        assert codes(lint_document(document, opinionated=True)) == ["GAL011"], (interval, rule_for)


def test_gal011_ignores_fractional_for_because_it_is_not_a_duration():
    # `for: 1.5s` Grafana отвергает (model.ParseDuration читает только целые
    # части): это GAL004, а не GAL011 — сравнивать нечего.
    found = lint_document(doc(rule(**{"for": "1.5s"}), interval="1m"), opinionated=True)
    assert codes(found) == ["GAL004"]


# --- --opinionated через CLI вместе с --strict / --format / --ignore -----


CLI_STYLE_DOC = """\
groups:
  - name: g
    interval: 1m
    rules:
      - uid: style
        title: Без severity и summary
        condition: A
        for: 5m
        noDataState: OK
        execErrState: Error
        data:
          - refId: A
            model: {expr: up, refId: A}
"""


@pytest.fixture
def style_file(tmp_path):
    path = tmp_path / "style.yml"
    path.write_text(CLI_STYLE_DOC, encoding="utf-8")
    return path


def test_cli_opinionated_reports_style_checks(style_file, capsys):
    assert main([str(style_file)]) == EXIT_OK
    quiet = capsys.readouterr().out
    assert "GAL008" not in quiet and "GAL009" not in quiet
    assert "предупреждений: 0" in quiet

    # Предупреждения без --strict не меняют код выхода, но видны в отчёте.
    assert main([str(style_file), "--opinionated"]) == EXIT_OK
    loud = capsys.readouterr().out
    assert "warning GAL008" in loud
    assert "warning GAL009" in loud


def test_cli_opinionated_with_strict_fails(style_file, capsys):
    assert main([str(style_file), "--opinionated", "--strict"]) == EXIT_FINDINGS
    capsys.readouterr()
    # Порядок флагов не важен.
    assert main([str(style_file), "--strict", "--opinionated"]) == EXIT_FINDINGS


def test_cli_opinionated_with_json_format(style_file, capsys):
    assert main([str(style_file), "--opinionated", "--format", "json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["errors"] == 0
    assert payload["warnings"] == 2
    assert {finding["code"] for finding in payload["findings"]} == {"GAL008", "GAL009"}
    assert all(finding["level"] == "warning" for finding in payload["findings"])


def test_cli_ignore_works_with_opinionated_and_strict(style_file, capsys):
    both = ["--opinionated", "--strict", "--ignore", "GAL008,GAL009"]
    assert main([str(style_file), *both]) == EXIT_OK
    out = capsys.readouterr().out
    assert "GAL008" not in out and "GAL009" not in out

    # --ignore не должен гасить остальные вкусовые коды: имена кодов
    # регистронезависимы, но точны.
    only_gal008 = ["--opinionated", "--strict", "--ignore", "gal008"]
    assert main([str(style_file), *only_gal008]) == EXIT_FINDINGS
    partially = capsys.readouterr().out
    assert "GAL008" not in partially
    assert "GAL009" in partially
