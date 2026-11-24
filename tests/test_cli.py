"""Проверки CLI: коды возврата, форматы, разворот каталогов."""

from __future__ import annotations

import json
from pathlib import Path

from grafana_alert_lint.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main

FIXTURES = Path(__file__).parent / "fixtures"
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

WARN_ONLY = """\
groups:
  - name: g
    interval: 1m
    rules:
      - uid: warn
        title: Только предупреждение
        condition: A
        for: 5m
        noDataState: NoData
        execErrState: Error
        labels: {severity: warning}
        annotations: {summary: 'нет данных'}
        data:
          - refId: A
            model: {expr: up, refId: A}
"""


def test_clean_file_returns_zero(capsys):
    assert main([str(FIXTURES / "clean.yml")]) == EXIT_OK
    assert "ошибок: 0" in capsys.readouterr().out


def test_errors_return_one(tmp_path, capsys):
    path = tmp_path / "broken.yml"
    path.write_text(BROKEN, encoding="utf-8")
    assert main([str(path)]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "error GAL005" in out


def test_strict_promotes_warnings(tmp_path):
    path = tmp_path / "warn.yml"
    path.write_text(WARN_ONLY, encoding="utf-8")
    assert main([str(path)]) == EXIT_OK
    assert main([str(path), "--strict"]) == EXIT_FINDINGS


def test_json_format(tmp_path, capsys):
    path = tmp_path / "broken.yml"
    path.write_text(BROKEN, encoding="utf-8")
    assert main([str(path), "--format", "json"]) == EXIT_FINDINGS
    payload = json.loads(capsys.readouterr().out)
    assert payload["errors"] == 1
    assert payload["findings"][0]["code"] == "GAL005"
    assert {"code", "level", "path", "group", "rule", "message"} == set(payload["findings"][0])


def test_directory_is_expanded_and_skips_venv(tmp_path, capsys):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "rules.yml").write_text(BROKEN, encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "noise.yml").write_text(BROKEN, encoding="utf-8")
    (tmp_path / "notes.txt").write_text("не yaml", encoding="utf-8")
    assert main([str(tmp_path), "--format", "json"]) == EXIT_FINDINGS
    payload = json.loads(capsys.readouterr().out)
    assert payload["errors"] == 1


def test_missing_path_is_usage_error(capsys):
    assert main(["/nope/rules.yml"]) == EXIT_USAGE
    assert "нет такого файла" in capsys.readouterr().err


def test_broken_yaml_is_usage_error(tmp_path, capsys):
    path = tmp_path / "bad.yml"
    path.write_text("groups: [", encoding="utf-8")
    assert main([str(path)]) == EXIT_USAGE
    assert "YAML не разбирается" in capsys.readouterr().err


def test_multiple_documents(tmp_path):
    path = tmp_path / "multi.yml"
    path.write_text(
        "groups: []\n---\n" + BROKEN, encoding="utf-8"
    )
    assert main([str(path)]) == EXIT_FINDINGS
