"""Регрессии по итогам аудита 2026-11-24.

Каждый тест здесь появился потому, что аудит нашёл дефект: ложное
срабатывание на валидном провижининге, пропуск настоящей ошибки или потеря
находок в CLI. Названия говорят, что именно защищено.
"""

from __future__ import annotations

import json

import pytest
import yaml

from grafana_alert_lint.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main
from grafana_alert_lint.linter import LintState, is_filtering_expression, lint_document, lint_path

BROKEN = """\
groups:
  - name: g
    interval: 1m
    rules:
      - uid: old
        title: Старое правило
        condition: A
        for: 5m
        noDataState: OK
        execErrState: Error
        labels: {severity: critical}
        annotations: {summary: 'диск <10%'}
        data:
          - refId: A
            model: {expr: up, refId: A}
"""


def rule(**overrides):
    base = {
        "uid": "r1",
        "title": "Правило",
        "condition": "B",
        "for": "5m",
        "noDataState": "OK",
        "execErrState": "Error",
        "labels": {"severity": "warning"},
        "annotations": {"summary": "Свободно меньше 10 процентов"},
        "data": [
            {"refId": "A", "model": {"expr": "up", "refId": "A"}},
            {"refId": "B", "model": {"type": "threshold", "expression": "A", "refId": "B"}},
        ],
    }
    base.update(overrides)
    return {"groups": [{"name": "g", "interval": "1m", "rules": [base]}]}


def codes(doc, **kwargs):
    return [finding.code for finding in lint_document(doc, **kwargs)]


# --- ложные срабатывания на валидном провижининге -------------------------


@pytest.mark.parametrize("value", ["OK", "Alerting", "NoData", "KeepLast"])
def test_no_data_state_accepts_all_grafana_values(value):
    expected = ["GAL002"] if value == "NoData" else []  # NoData — валидно, но опасное
    assert codes(rule(noDataState=value)) == expected


@pytest.mark.parametrize("value", ["OK", "Alerting", "Error", "KeepLast"])
def test_exec_err_state_accepts_all_grafana_values(value):
    assert codes(rule(execErrState=value)) == []


def test_no_data_state_error_is_rejected():
    # `Error` — значение execErrState, а не noDataState: Grafana правило отвергнет.
    assert codes(rule(noDataState="Error")) == ["GAL003"]


@pytest.mark.parametrize(
    "expr",
    [
        'up{version="1 == 0"}',
        'up{msg="x != 5"}',
        'up{job="node", note="a > b"}',
    ],
)
def test_comparison_inside_label_matcher_is_not_filtering(expr):
    assert is_filtering_expression(expr) is False
    data = [{"refId": "A", "model": {"expr": expr, "refId": "A"}}]
    assert codes(rule(noDataState="Alerting", condition="A", data=data)) == []


@pytest.mark.parametrize("expr", ["up == bool 0", "up != bool 1", "rate(x[5m]) >= bool 1"])
def test_bool_modifier_is_not_filtering(expr):
    assert is_filtering_expression(expr) is False


# --- пропущенные настоящие ошибки ----------------------------------------


@pytest.mark.parametrize("expr", ["up == 0", "up != 1", "up > 0", "up < 1", "up >= 1", "up <= 0"])
def test_all_comparison_operators_are_filtering(expr):
    assert is_filtering_expression(expr) is True
    assert "GAL001" in codes(
        rule(noDataState="Alerting", data=[{"refId": "A", "model": {"expr": expr, "refId": "A"}}])
    )


def test_integer_uid_duplicate_is_caught():
    first = rule(uid=1, title="Первое")
    second = rule(uid=1, title="Второе")
    doc = {"groups": [{"name": "g", "interval": "1m", "rules": [first["groups"][0]["rules"][0], second["groups"][0]["rules"][0]]}]}
    assert codes(doc) == ["GAL007"]


def test_duplicate_uid_across_documents_with_shared_state():
    state = LintState()
    first = rule(uid="same", title="Первое")
    second = rule(uid="same", title="Второе")
    assert codes(first, state=state) == []
    assert codes(second, state=state) == ["GAL007"]


def test_condition_with_empty_data_is_error():
    assert "GAL006" in codes(rule(data=[]))


def test_rule_without_data_is_error():
    doc = rule()
    del doc["groups"][0]["rules"][0]["data"]
    assert "GAL006" in codes(doc)


def test_group_without_interval_uses_grafana_default():
    doc = rule(**{"for": "30s"})
    del doc["groups"][0]["interval"]
    assert "GAL011" in codes(doc)


@pytest.mark.parametrize("value", ["1w", "1.5s", "2y", "1h30m"])
def test_parse_duration_extended_units(value):
    from grafana_alert_lint.linter import parse_duration

    assert parse_duration(value) is not None


def test_for_zero_is_not_missing_debounce():
    assert codes(rule(**{"for": 0})) == []


# --- устойчивость к кривому входу ----------------------------------------


def test_non_dict_group_rule_and_data_are_skipped():
    doc = {
        "groups": [
            "мусор",
            {"name": "g", "rules": [1, "строка", {"uid": "r", "title": "t", "condition": "A",
                                                 "for": "1m", "noDataState": "OK",
                                                 "execErrState": "OK", "labels": {"severity": "x"},
                                                 "annotations": {"summary": "x"},
                                                 "data": ["x", {"refId": "A", "model": "notadict"}]}]},
        ]
    }
    findings = lint_document(doc)
    assert isinstance(findings, list)


def test_annotations_non_dict_warns_but_does_not_crash():
    assert codes(rule(annotations=["a", "b"])) == ["GAL009"]


def test_non_string_annotation_is_ignored():
    assert codes(rule(annotations={"summary": "ok", "n": 5})) == []


def test_unreadable_path_raises_lint_error(tmp_path):
    from grafana_alert_lint.linter import LintError

    path = tmp_path / "directory.yml"
    path.mkdir()
    with pytest.raises(LintError):
        lint_path(path)


# --- CLI: находки не теряются --------------------------------------------


def test_findings_are_kept_when_another_path_is_missing(tmp_path, capsys):
    good = tmp_path / "good.yml"
    good.write_text(BROKEN, encoding="utf-8")
    assert main([str(good), str(tmp_path / "nope.yml")]) == EXIT_USAGE
    captured = capsys.readouterr()
    assert "error GAL005" in captured.out
    assert "нет такого файла" in captured.err


def test_json_output_survives_path_errors(tmp_path, capsys):
    good = tmp_path / "good.yml"
    good.write_text(BROKEN, encoding="utf-8")
    assert main([str(good), str(tmp_path / "nope.yml"), "--format", "json"]) == EXIT_USAGE
    payload = json.loads(capsys.readouterr().out)
    assert payload["errors"] == 1
    assert payload["path_errors"]


def test_multiple_files_share_uid_registry(tmp_path, capsys):
    first = tmp_path / "a.yml"
    second = tmp_path / "b.yml"
    first.write_text("groups: [{name: g, interval: 1m, rules: [{uid: shared, title: A, condition: A, for: 1m, noDataState: OK, execErrState: OK, labels: {severity: x}, annotations: {summary: x}, data: [{refId: A, model: {expr: up, refId: A}}]}]}]\n", encoding="utf-8")
    second.write_text("groups: [{name: g2, interval: 1m, rules: [{uid: shared, title: B, condition: A, for: 1m, noDataState: OK, execErrState: OK, labels: {severity: x}, annotations: {summary: x}, data: [{refId: A, model: {expr: up, refId: A}}]}]}]\n", encoding="utf-8")
    assert main([str(first), str(second)]) == EXIT_FINDINGS
    assert "GAL007" in capsys.readouterr().out


def test_clean_run_exits_zero_without_leading_blank(tmp_path, capsys):
    path = tmp_path / "clean.yml"
    path.write_text(yaml.safe_dump(rule()), encoding="utf-8")
    assert main([str(path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("ошибок: 0")
