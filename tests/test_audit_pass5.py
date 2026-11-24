"""Пятый проход аудита 2026-11-24: границы уникальности, вкусовые проверки, CLI.

Каждый тест здесь защищает конкретную находку аудита (A01–A09 в
`AUDIT-2026-11-24-pass5.md`).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from grafana_alert_lint import __version__
from grafana_alert_lint.cli import EXIT_OK, EXIT_USAGE, collect_paths, main
from grafana_alert_lint.linter import Finding, LintState, lint_document

ROOT = Path(__file__).resolve().parents[1]


def rule(uid: str = "r1", title: str = "Правило", **overrides):
    base = {
        "uid": uid,
        "title": title,
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


def doc(*rules, group: str = "g", org_id: object = 1, folder: str | None = "F"):
    group_doc: dict[str, object] = {"name": group, "interval": "1m", "rules": list(rules)}
    if org_id is not None:
        group_doc["orgId"] = org_id
    if folder is not None:
        group_doc["folder"] = folder
    return {"groups": [group_doc]}


def codes(findings: list[Finding]) -> list[str]:
    return [finding.code for finding in findings]


# --- A01/A03: title уникален для (org, folder), а не для группы ----------


def test_same_title_in_same_folder_different_groups_is_warning():
    findings = lint_document(
        {
            "groups": [
                {"name": "g1", "folder": "F", "rules": [rule(uid="a", title="Disk full")]},
                {"name": "g2", "folder": "F", "rules": [rule(uid="b", title="Disk full")]},
            ]
        }
    )
    duplicate = [f for f in findings if f.code == "GAL007"]
    assert len(duplicate) == 1
    assert duplicate[0].level == "warning"


def test_same_title_in_different_folders_is_clean():
    findings = lint_document(
        {
            "groups": [
                {"name": "node", "folder": "A", "rules": [rule(uid="a", title="Disk full")]},
                {"name": "node", "folder": "B", "rules": [rule(uid="b", title="Disk full")]},
            ]
        }
    )
    assert "GAL007" not in codes(findings)


def test_same_title_in_different_orgs_is_clean():
    findings = lint_document(
        {
            "groups": [
                {"name": "g", "orgId": 1, "folder": "F", "rules": [rule(uid="a", title="T")]},
                {"name": "g", "orgId": 2, "folder": "F", "rules": [rule(uid="b", title="T")]},
            ]
        }
    )
    assert "GAL007" not in codes(findings)


# --- A02: uid уникален в пределах org ------------------------------------


def test_same_uid_in_different_orgs_is_clean():
    findings = lint_document(
        {
            "groups": [
                {"name": "g", "orgId": 1, "rules": [rule(uid="shared")]},
                {"name": "g2", "orgId": 2, "rules": [rule(uid="shared", title="Другое")]},
            ]
        }
    )
    assert "GAL007" not in codes(findings)


def test_same_uid_in_same_org_is_error_across_folders():
    findings = lint_document(
        {
            "groups": [
                {"name": "g", "orgId": 1, "folder": "A", "rules": [rule(uid="shared")]},
                {
                    "name": "g2",
                    "orgId": 1,
                    "folder": "B",
                    "rules": [rule(uid="shared", title="Другое")],
                },
            ]
        }
    )
    duplicate = [f for f in findings if f.code == "GAL007"]
    assert len(duplicate) == 1
    assert duplicate[0].level == "error"
    assert "orgId=1" in duplicate[0].message


def test_state_is_shared_between_documents_including_org():
    state = LintState()
    assert codes(lint_document(doc(rule(uid="x"), org_id=1), state=state)) == []
    assert "GAL007" not in codes(lint_document(doc(rule(uid="x"), org_id=2), state=state))
    assert "GAL007" in codes(lint_document(doc(rule(uid="x"), org_id=1), state=state))


# --- A08: вкусовые проверки молчат без --opinionated ---------------------


STYLE_ONLY = doc(rule(labels={}, noDataState="NoData"))


def test_style_checks_are_silent_by_default():
    findings = lint_document(STYLE_ONLY)
    assert codes(findings) == []


def test_style_checks_fire_with_opinionated():
    assert set(codes(lint_document(STYLE_ONLY, opinionated=True))) == {"GAL002", "GAL008"}


def test_opinionated_reaches_cli(tmp_path, capsys):
    path = tmp_path / "style.yml"
    path.write_text(
        "groups:\n"
        "  - name: g\n"
        "    interval: 1m\n"
        "    rules:\n"
        "      - uid: w\n"
        "        title: Без severity\n"
        "        condition: A\n"
        "        for: 5m\n"
        "        noDataState: OK\n"
        "        execErrState: OK\n"
        "        annotations: {summary: x}\n"
        "        data: [{refId: A, model: {expr: up}}]\n",
        encoding="utf-8",
    )
    assert main([str(path)]) == EXIT_OK
    capsys.readouterr()
    assert main([str(path), "--opinionated"]) == EXIT_OK
    assert "GAL008" in capsys.readouterr().out


# --- A06: невалидный interval группы — находка, а не подстановка 60 с ----


def test_broken_group_interval_is_reported():
    findings = lint_document(
        {"groups": [{"name": "g", "interval": "jedes Mal", "rules": [rule(**{"for": "30s"})]}]}
    )
    codes_found = codes(findings)
    assert "GAL013" in codes_found
    assert "GAL011" not in codes_found  # чужое «60s» в сообщении больше не выдумывается
    gal013 = next(f for f in findings if f.code == "GAL013")
    assert gal013.level == "error"
    assert gal013.rule == "(группа)"


def test_missing_group_interval_is_not_reported():
    findings = lint_document({"groups": [{"name": "g", "rules": [rule(**{"for": "2m"})]}]})
    assert "GAL013" not in codes(findings)


def test_numeric_group_interval_is_valid():
    findings = lint_document({"groups": [{"name": "g", "interval": 60, "rules": [rule()]}]})
    assert "GAL013" not in codes(findings)


# --- A04: отрицательный --max-file-size — ошибка ввода -------------------


@pytest.mark.parametrize("value", ["-1", "-9999"])
def test_negative_max_file_size_is_usage_error(tmp_path, capsys, value):
    path = tmp_path / "rules.yml"
    path.write_text("groups: []\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main([str(path), "--max-file-size", value])
    assert exc.value.code == 2
    assert "отрицательный" in capsys.readouterr().err


def test_non_numeric_max_file_size_is_usage_error(tmp_path, capsys):
    path = tmp_path / "rules.yml"
    path.write_text("groups: []\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main([str(path), "--max-file-size", "много"])
    assert exc.value.code == 2
    assert "целое число" in capsys.readouterr().err


def test_max_file_size_zero_still_disables_limit(tmp_path):
    path = tmp_path / "rules.yml"
    path.write_text("groups: []\n", encoding="utf-8")
    assert main([str(path), "--max-file-size", "0"]) == EXIT_OK


# --- A07: версия — один источник -----------------------------------------


def test_pyproject_has_no_static_version():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "0.1.0"' not in text
    assert 'dynamic = ["version"]' in text
    assert 'attr = "grafana_alert_lint.__version__"' in text


def test_cli_version_matches_package(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_python_dash_m_works():
    result = subprocess.run(
        [sys.executable, "-m", "grafana_alert_lint", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert __version__ in result.stdout


def test_unreadable_dir_is_still_exit_usage(monkeypatch, tmp_path):
    # Страховка: любая неожиданная ошибка по пути — код 2, а не трейсбек.
    path = tmp_path / "rules.yml"
    path.write_text("groups: []\n", encoding="utf-8")

    def boom(*args, **kwargs):
        raise RuntimeError("внутренняя поломка")

    monkeypatch.setattr("grafana_alert_lint.cli.lint_path", boom)
    assert main([str(path)]) == EXIT_USAGE


# --- находки четырёх проверяющих агентов (2026-11-24) ---------------------


def test_fractional_duration_is_not_grafana_duration():
    # model.ParseDuration (prometheus/common) читает только целые части.
    from grafana_alert_lint.linter import parse_duration

    assert parse_duration("1.5s") is None
    assert parse_duration("0.5m") is None
    assert parse_duration("1h30m") == 5400.0
    assert parse_duration("1w") == 604800.0


def test_fractional_for_is_reported(tmp_path):
    doc = {"groups": [{"name": "g", "interval": "1m", "rules": [rule(**{"for": "1.5s"})]}]}
    findings = lint_document(doc, opinionated=True)
    assert ("GAL004", "warning") in [(f.code, f.level) for f in findings]


def test_record_title_takes_a_name_in_the_folder():
    recording = {"uid": "rec", "title": "Same", "record": {"from": "A", "metric": "m"}}
    alert = rule(uid="a", title="Same")
    findings = lint_document(
        {"groups": [{"name": "g", "orgId": 1, "folder": "F", "rules": [recording, alert]}]}
    )
    assert "GAL007" in codes(findings)


def test_numeric_org_id_is_normalized():
    findings = lint_document(
        {
            "groups": [
                {"name": "g", "orgId": 1.0, "rules": [rule(uid="dup")]},
                {"name": "g2", "orgId": 1, "rules": [rule(uid="dup", title="Другое")]},
            ]
        }
    )
    assert "GAL007" in codes(findings)


def test_huge_interval_does_not_lose_findings(tmp_path, capsys):
    path = tmp_path / "huge.yml"
    path.write_text(
        "groups:\n"
        "  - name: g\n"
        "    interval: " + "9" * 400 + "\n"
        "    rules:\n"
        "      - uid: dup\n"
        "        title: A\n"
        "        condition: A\n"
        "        for: 2m\n"
        "        noDataState: OK\n"
        "        execErrState: OK\n"
        "        labels: {severity: x}\n"
        "        annotations: {summary: x}\n"
        "        data: [{refId: A, model: {expr: up}}]\n"
        "      - uid: dup\n"
        "        title: B\n"
        "        condition: A\n"
        "        for: 2m\n"
        "        noDataState: OK\n"
        "        execErrState: OK\n"
        "        labels: {severity: x}\n"
        "        annotations: {summary: x}\n"
        "        data: [{refId: A, model: {expr: up}}]\n",
        encoding="utf-8",
    )
    assert main([str(path)]) == 1  # находки есть, трейсбека нет
    out = capsys.readouterr().out
    assert "GAL013" in out
    assert "GAL007" in out


def test_surrogate_in_yaml_does_not_crash_cli(tmp_path):
    path = tmp_path / "surrogate.yml"
    path.write_text(
        "groups:\n"
        "  - name: g\n"
        "    interval: 1m\n"
        "    rules:\n"
        '      - uid: "a\\ud800"\n'
        "        title: T\n"
        "        condition: A\n"
        "        for: 2m\n"
        "        noDataState: Bad\n"
        "        execErrState: OK\n"
        "        labels: {severity: x}\n"
        "        annotations: {summary: x}\n"
        "        data: [{refId: A, model: {expr: up}}]\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, "-m", "grafana_alert_lint", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "Traceback" not in result.stderr
    assert result.returncode == 1
    assert "GAL003" in result.stdout


@pytest.mark.skipif(not hasattr(__import__("os"), "mkfifo"), reason="нужен mkfifo")
def test_fifo_argument_says_not_a_regular_file(tmp_path, capsys):
    import os

    fifo = tmp_path / "pipe.yml"
    os.mkfifo(fifo)
    assert main([str(fifo)]) == EXIT_USAGE
    assert "не обычный файл" in capsys.readouterr().err


def test_ignore_is_case_insensitive(tmp_path, capsys):
    path = tmp_path / "broken.yml"
    path.write_text(
        "groups:\n"
        "  - name: g\n"
        "    interval: 1m\n"
        "    rules:\n"
        "      - uid: r\n"
        "        title: T\n"
        "        condition: A\n"
        "        for: 2m\n"
        "        noDataState: OK\n"
        "        execErrState: OK\n"
        "        labels: {severity: x}\n"
        "        annotations: {summary: 'a < b'}\n"
        "        data: [{refId: A, model: {expr: up}}]\n",
        encoding="utf-8",
    )
    assert main([str(path), "--ignore", "gal005"]) == EXIT_OK
    assert "GAL005" not in capsys.readouterr().out


def test_uppercase_suffix_is_linted(tmp_path):
    path = tmp_path / "RULES.YML"
    path.write_text("groups: []\n", encoding="utf-8")
    files, errors = collect_paths([tmp_path])
    assert errors == []
    assert files == [path]


def test_finding_label_prefers_title():
    findings = lint_document(doc(rule(uid="u", title="Человеческое", noDataState="Bad")))
    assert findings[0].rule == "Человеческое"


def test_style_checks_are_silent_individually():
    for overrides in ({"labels": {}}, {"execErrState": None}, {"for": None}):
        assert codes(lint_document(doc(rule(**overrides)))) == []
