"""Проверки линтера на разборе реальных дефектов."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from grafana_alert_lint.linter import (
    Finding,
    lint_document,
    lint_path,
    parse_duration,
    query_expressions,
)

FIXTURES = Path(__file__).parent / "fixtures"


def codes(text: str) -> list[Finding]:
    return lint_document(yaml.safe_load(text))


def base_rule(**overrides):
    rule = {
        "uid": "r1",
        "title": "Правило",
        "condition": "B",
        "for": "5m",
        "noDataState": "OK",
        "execErrState": "Error",
        "labels": {"severity": "warning"},
        "annotations": {"summary": "Свободно меньше 10 процентов"},
        "data": [
            {
                "refId": "A",
                "model": {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "expr": "up",
                    "refId": "A",
                },
            },
            {
                "refId": "B",
                "model": {"datasource": {"type": "__expr__", "uid": "__expr__"}, "expression": "A", "refId": "B"},
            },
        ],
    }
    rule.update(overrides)
    return {"groups": [{"name": "g", "interval": "1m", "rules": [rule]}]}


def codes_of(doc) -> list[str]:
    return [finding.code for finding in lint_document(doc)]


def test_clean_fixture_is_clean():
    assert lint_path(FIXTURES / "clean.yml") == []


def test_regression_0003_is_caught():
    findings = lint_path(FIXTURES / "regression-0003.yml")
    assert [f.code for f in findings] == ["GAL001"]
    assert findings[0].level == "error"
    assert "застрянет в Firing" in findings[0].message


def test_filtering_expression_with_alerting_no_data():
    assert codes_of(base_rule(noDataState="Alerting", data=[
        {"refId": "A", "model": {"expr": "up{job=\"node\"} != 1", "refId": "A"}},
        {"refId": "B", "model": {"type": "threshold", "expression": "A", "refId": "B"}},
    ])) == ["GAL001"]


def test_raw_metric_with_alerting_is_allowed():
    # Порог живёт в threshold, а не в PromQL: пустой серии нет.
    assert codes_of(base_rule(noDataState="Alerting")) == []


def test_no_data_state_missing():
    rule = base_rule()
    del rule["groups"][0]["rules"][0]["noDataState"]
    assert "GAL003" in codes_of(rule)


def test_no_data_state_unknown_value():
    assert "GAL003" in codes_of(base_rule(noDataState="Sometimes"))


def test_no_data_state_no_data_warns():
    findings = lint_document(base_rule(noDataState="NoData"))
    assert [f.code for f in findings] == ["GAL002"]
    assert findings[0].level == "warning"


def test_missing_for():
    rule = base_rule()
    del rule["groups"][0]["rules"][0]["for"]
    assert "GAL004" in codes_of(rule)


@pytest.mark.parametrize("text", ["диск меньше <10%", "up > 0 и всё"])
def test_html_unsafe_annotation(text):
    assert "GAL005" in codes_of(base_rule(annotations={"summary": text}))


def test_angle_bracket_in_description():
    rule = base_rule(annotations={"summary": "ок", "description": "если < 5 минут"})
    assert "GAL005" in codes_of(rule)


def test_condition_refers_to_missing_ref_id():
    assert "GAL006" in codes_of(base_rule(condition="C"))


def test_condition_missing():
    rule = base_rule()
    del rule["groups"][0]["rules"][0]["condition"]
    assert "GAL006" in codes_of(rule)


def test_duplicate_uid_is_error():
    rule = base_rule()
    rule["groups"][0]["rules"].append(dict(rule["groups"][0]["rules"][0]))
    doc = rule
    findings = lint_document(doc)
    assert "GAL007" in [f.code for f in findings]


def test_severity_missing_warns():
    rule = base_rule(labels={})
    assert "GAL008" in codes_of(rule)


def test_summary_missing_warns():
    rule = base_rule(annotations={})
    assert "GAL009" in codes_of(rule)


def test_exec_err_state_missing_warns():
    rule = base_rule()
    del rule["groups"][0]["rules"][0]["execErrState"]
    assert "GAL010" in codes_of(rule)


def test_for_shorter_than_interval_warns():
    assert "GAL011" in codes_of(base_rule(**{"for": "30s"}))


def test_rule_without_identity_is_error():
    rule = base_rule(uid=None, title=None)
    assert "GAL012" in codes_of(rule)


def test_query_expressions_skip_expr_models():
    rule = base_rule()["groups"][0]["rules"][0]
    assert query_expressions(rule) == ["up"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [("30s", 30.0), ("1m", 60.0), ("1h30m", 5400.0), ("2d", 172800.0), ("", None), ("5", None), ("1x", None)],
)
def test_parse_duration(value, expected):
    assert parse_duration(value) == expected


def test_parse_duration_numeric():
    assert parse_duration(90) == 90.0


def test_non_dict_documents_are_ignored():
    assert lint_document([1, 2, 3]) == []
    assert lint_document(None) == []
