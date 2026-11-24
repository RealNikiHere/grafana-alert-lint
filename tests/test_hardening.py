"""Второй проход аудита 2026-11-24: устойчивость к кривому входу и CLI.

Здесь всё, что раньше падало трейсбеком, давало ложный дубль или молчало
там, где должно было сообщить об ошибке.
"""

from __future__ import annotations

import os

import pytest

from grafana_alert_lint.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, collect_paths, main
from grafana_alert_lint.linter import (
    is_filtering_expression,
    lint_document,
    lint_path,
    parse_duration,
)

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
    return [(f.code, f.level) for f in lint_document(doc, **kwargs)]


# --- скаляр там, где ожидается список: не падаем -------------------------


@pytest.mark.parametrize(
    "doc",
    [
        {"groups": 5},
        {"groups": [{"name": "g", "rules": 5}]},
        {"groups": [{"name": "g", "rules": [{"uid": "r", "title": "t", "data": 5}]}]},
    ],
)
def test_scalar_instead_of_list_does_not_crash(doc):
    assert isinstance(lint_document(doc), list)


def test_scalar_data_still_reports_missing_condition():
    doc = rule(data=5)
    assert ("GAL006", "error") in codes(doc)


# --- кодировки и чтение файлов -------------------------------------------


def test_non_utf8_file_becomes_lint_error_instead_of_traceback(tmp_path, capsys):
    path = tmp_path / "latin1.yml"
    path.write_bytes(b"groups: [{name: g, title: '\xe9'}]\n")
    assert main([str(path)]) == EXIT_USAGE
    captured = capsys.readouterr()
    assert "не читается" in captured.err
    assert "Traceback" not in captured.err


def test_unreadable_file_is_error(tmp_path):
    path = tmp_path / "dir.yml"
    path.mkdir()
    from grafana_alert_lint.linter import LintError

    with pytest.raises(LintError):
        lint_path(path)


@pytest.mark.skipif(os.geteuid() == 0, reason="root читает каталог независимо от прав")
def test_unreadable_directory_is_reported(tmp_path, capsys):
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "rules.yml").write_text(BROKEN, encoding="utf-8")
    blocked.chmod(0o000)
    try:
        assert main([str(blocked)]) == EXIT_USAGE
        assert "blocked" in capsys.readouterr().err
    finally:
        blocked.chmod(0o755)


# --- дубли путей не дают ложный GAL007 -----------------------------------


def test_same_file_twice_is_checked_once(tmp_path):
    path = tmp_path / "clean.yml"
    path.write_text(BROKEN.replace("'диск <10%'", "'диск'"), encoding="utf-8")
    files, errors = collect_paths([path, path])
    assert errors == []
    assert files == [path]


def test_directory_and_file_inside_it_do_not_duplicate(tmp_path):
    path = tmp_path / "rules.yml"
    path.write_text(BROKEN.replace("'диск <10%'", "'диск'"), encoding="utf-8")
    files, errors = collect_paths([tmp_path, path])
    assert errors == []
    assert files == [path]


def test_duplicate_paths_do_not_produce_gal007(tmp_path, capsys):
    path = tmp_path / "clean.yml"
    path.write_text(BROKEN.replace("'диск <10%'", "'диск'"), encoding="utf-8")
    assert main([str(path), str(path), str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "GAL007" not in out


# --- backtick-строки в PromQL --------------------------------------------


def test_backtick_raw_string_is_not_a_comparison():
    assert is_filtering_expression("up{note=`a}b == c`}") is False


def test_backtick_string_with_operator_does_not_trigger_gal001():
    data = [{"refId": "A", "model": {"expr": "up{note=`a}b == c`}", "refId": "A"}}]
    assert codes(rule(noDataState="Alerting", condition="A", data=data)) == []


# --- уровни и частичная идентичность ------------------------------------


def test_duplicate_title_with_different_uids_is_error():
    first = rule(uid="a", title="Одинаковый")["groups"][0]["rules"][0]
    second = rule(uid="b", title="Одинаковый")["groups"][0]["rules"][0]
    doc = {"groups": [{"name": "g", "interval": "1m", "rules": [first, second]}]}
    assert ("GAL007", "error") in codes(doc)


def test_invalid_exec_err_state_is_warning():
    assert codes(rule(execErrState="NoData")) == [("GAL010", "warning")]


@pytest.mark.parametrize("overrides", [{"uid": None}, {"title": None}])
def test_partial_identity_is_not_gal012(overrides):
    assert codes(rule(**overrides)) == []


def test_error_levels_are_stable():
    expected = {
        "GAL003": "error",
        "GAL004": "warning",
        "GAL008": "warning",
        "GAL009": "warning",
        "GAL010": "warning",
    }
    found = dict(codes(rule(uid=None, title=None, **{"for": None}, noDataState="Error", labels={}, annotations={}, execErrState=None)))
    for code, level in expected.items():
        assert found.get(code) == level, (code, found)


def test_for_equal_to_interval_does_not_warn():
    assert "GAL011" not in [code for code, _ in codes(rule(**{"for": "1m"}))]


def test_for_longer_than_interval_does_not_warn():
    assert "GAL011" not in [code for code, _ in codes(rule(**{"for": "10m"}))]


def test_parse_duration_rejects_bool_and_gaps():
    assert parse_duration(True) is None
    assert parse_duration("1h 30m") is None
    assert parse_duration("5m5") is None


def test_error_findings_sort_before_warnings(tmp_path, capsys):
    path = tmp_path / "mixed.yml"
    path.write_text(
        "groups:\n"
        "  - name: g\n"
        "    interval: 1m\n"
        "    rules:\n"
        "      - uid: w\n"
        "        title: Warning first\n"
        "        condition: A\n"
        "        for: 5m\n"
        "        noDataState: NoData\n"
        "        execErrState: OK\n"
        "        labels: {severity: x}\n"
        "        annotations: {summary: x}\n"
        "        data: [{refId: A, model: {expr: up, refId: A}}]\n"
        "      - uid: e\n"
        "        title: Error second\n"
        "        condition: A\n"
        "        for: 5m\n"
        "        noDataState: OK\n"
        "        execErrState: OK\n"
        "        labels: {severity: x}\n"
        "        annotations: {summary: 'a < b'}\n"
        "        data: [{refId: A, model: {expr: up, refId: A}}]\n",
        encoding="utf-8",
    )
    assert main([str(path)]) == EXIT_FINDINGS
    lines = [line for line in capsys.readouterr().out.splitlines() if "GAL" in line]
    assert "error" in lines[0] and "warning" in lines[1]


def test_deeply_nested_yaml_is_an_error_not_a_traceback(tmp_path, capsys):
    path = tmp_path / "deep.yml"
    path.write_text("[" * 5000 + "]" * 5000, encoding="utf-8")
    assert main([str(path)]) == EXIT_USAGE
    captured = capsys.readouterr()
    assert "YAML не разбирается" in captured.err
    assert "Traceback" not in captured.err


# --- третий проход аудита: типы YAML и дедуп ----------------------------


def bare(**overrides):
    base = {
        "condition": "A",
        "for": "1m",
        "noDataState": "OK",
        "execErrState": "OK",
        "labels": {"severity": "x"},
        "annotations": {"summary": "s"},
        "data": [{"refId": "A", "model": {"expr": "up", "refId": "A"}}],
    }
    base.update(overrides)
    return base


def codes_of_rules(*rules):
    return [(f.code, f.level) for f in lint_document({"groups": [{"name": "g", "interval": "1m", "rules": list(rules)}]})]


@pytest.mark.parametrize(
    "rule",
    [
        bare(data=[{"refId": "A", "model": {"type": {"a": 1}, "expr": "up"}}]),
        bare(noDataState={"x": 1}),
        bare(data=[{"refId": {"a": 1}, "model": {"expr": "up"}}]),
        bare(data=[{"refId": 1, "model": {"expr": "up"}}, {"refId": "A", "model": {"expr": "up"}}]),
        bare(execErrState=["OK"]),
        bare(labels={"severity": {"a": 1}}),
        bare(annotations={"summary": ["a"]}),
        bare(condition={"a": 1}),
    ],
)
def test_unhashable_yaml_values_do_not_crash(rule):
    assert isinstance(lint_document({"groups": [{"name": "g", "rules": [rule]}]}), list)


def test_dict_no_data_state_is_reported():
    assert ("GAL003", "error") in codes_of_rules(bare(noDataState={"x": 1}, uid="u"))


def test_dict_ref_id_does_not_kill_condition_check():
    codes = codes_of_rules(bare(data=[{"refId": {"a": 1}, "model": {"expr": "up"}}], uid="u"))
    assert ("GAL006", "error") in codes


def test_uid_of_one_rule_is_not_title_duplicate_of_another():
    # uid="x" без title и title="x" без uid — разные правила, дубля нет.
    assert codes_of_rules(bare(uid="x"), bare(title="x")) == []


def test_missing_title_does_not_collide_across_rules():
    assert codes_of_rules(bare(uid="a"), bare(uid="b")) == []


def test_numeric_zero_uid_is_a_uid():
    assert codes_of_rules(bare(uid=0)) == []


@pytest.mark.parametrize("bad_for", [False, ["1m"], {"v": 1}])
def test_invalid_for_type_is_reported(bad_for):
    assert ("GAL004", "warning") in codes_of_rules(bare(uid="u", **{"for": bad_for}))


def test_findings_from_parsed_documents_survive_parse_error_later(tmp_path, capsys):
    path = tmp_path / "multi.yml"
    path.write_text(
        "groups:\n"
        "  - name: g\n"
        "    interval: 1m\n"
        "    rules:\n"
        "      - uid: ok\n"
        "        title: ok\n"
        "        condition: A\n"
        "        for: 5m\n"
        "        noDataState: OK\n"
        "        execErrState: OK\n"
        "        labels: {severity: x}\n"
        "        annotations: {summary: 'a < b'}\n"
        "        data: [{refId: A, model: {expr: up, refId: A}}]\n"
        "---\n"
        "groups: [\n",
        encoding="utf-8",
    )
    assert main([str(path)]) == EXIT_USAGE
    captured = capsys.readouterr()
    assert "GAL005" in captured.out
    assert "YAML не разбирается" in captured.err


def test_max_file_size_is_enforced(tmp_path, capsys):
    path = tmp_path / "big.yml"
    path.write_text("groups: []\n" + "# filler\n" * 100, encoding="utf-8")
    assert main([str(path), "--max-file-size", "10"]) == EXIT_USAGE
    assert "больше лимита" in capsys.readouterr().err


def test_max_file_size_zero_disables_limit(tmp_path):
    path = tmp_path / "big.yml"
    path.write_text("groups: []\n", encoding="utf-8")
    assert main([str(path), "--max-file-size", "0"]) == EXIT_OK


def test_threshold_model_without_expr_datasource_is_not_promql():
    model = {"type": "threshold", "expression": "A == 0", "refId": "B"}
    rule = bare(uid="u", noDataState="Alerting", condition="B", data=[{"refId": "B", "model": model}])
    assert codes_of_rules(rule) == []


def test_numeric_and_string_uid_collide():
    assert ("GAL007", "error") in codes_of_rules(bare(uid=1, title="a"), bare(uid="1", title="b"))


def test_parse_duration_and_as_list_contract():
    from grafana_alert_lint.linter import as_list

    assert parse_duration("1h30m") == 5400.0
    assert as_list("строка") == []
    assert as_list({"a": 1}) == []
