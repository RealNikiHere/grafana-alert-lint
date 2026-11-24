"""Контракт CLI `galint`: коды выхода, форматы, флаги, разворот каталогов.

Тема файла — именно наблюдаемый контракт процесса/`main()`: что попадает в
stdout, что в stderr, какой код вернётся и как выглядит JSON. Внутренние
проверки линтера здесь не тестируются (это tests/test_linter.py и соседи),
чтобы не дублировать существующий набор.

Запуск: `.venv/bin/python -m pytest .subagent-tests/t6 -q`
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from grafana_alert_lint import __version__
from grafana_alert_lint.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main

ROOT = Path(__file__).resolve().parents[2]

# Одно правило с настоящей ошибкой (GAL005: '<' в аннотации).
ERROR_YML = """\
groups:
  - name: zeta
    interval: 1m
    rules:
      - uid: e1
        title: Ошибка
        condition: A
        for: 5m
        noDataState: OK
        execErrState: Error
        labels: {severity: critical}
        annotations: {summary: 'диск <10%'}
        data: [{refId: A, model: {expr: up, refId: A}}]
"""

# Одно предупреждение без `--opinionated` (GAL007: повтор title в папке).
WARN_YML = """\
groups:
  - name: g
    interval: 1m
    rules:
      - uid: w1
        title: Дубль
        condition: A
        for: 5m
        noDataState: OK
        execErrState: Error
        labels: {severity: critical}
        annotations: {summary: ok}
        data: [{refId: A, model: {expr: up, refId: A}}]
      - uid: w2
        title: Дубль
        condition: A
        for: 5m
        noDataState: OK
        execErrState: Error
        labels: {severity: critical}
        annotations: {summary: ok}
        data: [{refId: A, model: {expr: up, refId: A}}]
"""

# Ошибка и предупреждение в одном файле; группы названы так, что алфавитный
# порядок (alpha/zeta) противоположен порядку «error перед warning».
MIXED_YML = """\
groups:
  - name: zeta
    interval: 1m
    rules:
      - uid: e1
        title: Ошибка
        condition: A
        for: 5m
        noDataState: OK
        execErrState: Error
        labels: {severity: critical}
        annotations: {summary: 'диск <10%'}
        data: [{refId: A, model: {expr: up, refId: A}}]
  - name: alpha
    interval: 1m
    rules:
      - uid: w1
        title: Дубль
        condition: A
        for: 5m
        noDataState: OK
        execErrState: Error
        labels: {severity: critical}
        annotations: {summary: ok}
        data: [{refId: A, model: {expr: up, refId: A}}]
      - uid: w2
        title: Дубль
        condition: A
        for: 5m
        noDataState: OK
        execErrState: Error
        labels: {severity: critical}
        annotations: {summary: ok}
        data: [{refId: A, model: {expr: up, refId: A}}]
"""


def write(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --- коды выхода 0 / 1 / 2 во всех сочетаниях -----------------------------


@pytest.mark.parametrize(
    ("name", "text", "extra", "expected"),
    [
        ("errors", ERROR_YML, [], EXIT_FINDINGS),
        ("errors-strict", ERROR_YML, ["--strict"], EXIT_FINDINGS),
        ("warnings", WARN_YML, [], EXIT_OK),
        ("warnings-strict", WARN_YML, ["--strict"], EXIT_FINDINGS),
        ("warnings-opinionated", WARN_YML, ["--opinionated"], EXIT_OK),
        ("warnings-both", WARN_YML, ["--opinionated", "--strict"], EXIT_FINDINGS),
        ("empty-file-strict", "", ["--strict"], EXIT_OK),
        ("errors-ignored", ERROR_YML, ["--ignore", "GAL005"], EXIT_OK),
    ],
)
def test_exit_code_matrix(tmp_path, name, text, extra, expected):
    path = write(tmp_path, f"{name}.yml", text)
    assert main([str(path), *extra]) == expected


def test_read_error_beats_findings_and_keeps_report(tmp_path, capsys):
    """Находки + ошибка чтения: код 2, но отчёт с находками не теряется."""
    good = write(tmp_path, "good.yml", WARN_YML)
    bad = write(tmp_path, "bad.yml", "groups: [\n")
    missing = tmp_path / "nope.yml"

    assert main([str(good), str(bad), str(missing), "--format", "json"]) == EXIT_USAGE
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["warnings"] == 1  # находки разобранных файлов на месте
    assert len(payload["path_errors"]) == 2  # битый YAML + несуществующий путь
    assert captured.err.count("galint: ") == 2
    assert "galint:" not in captured.out


def test_empty_file_and_empty_directory_are_clean(tmp_path, capsys):
    empty_file = write(tmp_path, "nothing.yml", "")
    empty_dir = tmp_path / "vacant"
    empty_dir.mkdir()

    assert main([str(empty_file)]) == EXIT_OK
    assert capsys.readouterr().out == "ошибок: 0, предупреждений: 0\n"

    assert main([str(empty_dir), "--strict", "--opinionated"]) == EXIT_OK
    captured = capsys.readouterr()
    assert captured.out == "ошибок: 0, предупреждений: 0\n"
    assert captured.err == ""


# --- --format json: схема -------------------------------------------------


def test_json_schema_key_order_and_types(tmp_path, capsys):
    path = write(tmp_path, "mixed.yml", MIXED_YML)
    assert main([str(path), "--format", "json"]) == EXIT_FINDINGS
    raw = capsys.readouterr().out

    payload = json.loads(raw)
    assert list(payload) == ["errors", "warnings", "path_errors", "findings"]
    assert isinstance(payload["errors"], int) and not isinstance(payload["errors"], bool)
    assert isinstance(payload["warnings"], int) and not isinstance(payload["warnings"], bool)
    assert isinstance(payload["path_errors"], list)
    assert isinstance(payload["findings"], list)

    for finding in payload["findings"]:
        assert list(finding) == ["code", "level", "path", "group", "rule", "message"]
        assert all(isinstance(value, str) for value in finding.values())
        assert finding["level"] in {"error", "warning"}
        assert finding["code"].startswith("GAL")


def test_json_counters_match_findings(tmp_path, capsys):
    path = write(tmp_path, "mixed.yml", MIXED_YML)
    main([str(path), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["errors"] == sum(1 for f in payload["findings"] if f["level"] == "error")
    assert payload["warnings"] == sum(1 for f in payload["findings"] if f["level"] == "warning")
    assert payload["errors"] + payload["warnings"] == len(payload["findings"])
    assert payload["errors"] == 1 and payload["warnings"] == 1  # ровно то, что в фикстуре


def test_json_keeps_cyrillic_unescaped_and_round_trips(tmp_path, capsys):
    path = write(tmp_path, "ru.yml", ERROR_YML)
    main([str(path), "--format", "json"])
    raw = capsys.readouterr().out

    assert "Ошибка" in raw  # ensure_ascii=False: кириллица не в \uXXXX
    assert "\\u" not in raw
    payload = json.loads(raw)  # валидный JSON
    assert payload["findings"][0]["rule"] == "Ошибка"
    assert payload["findings"][0]["code"] == "GAL005"
    assert payload["findings"][0]["message"]


def test_json_empty_run_keeps_full_schema(tmp_path, capsys):
    empty_dir = tmp_path / "vacant"
    empty_dir.mkdir()
    assert main([str(empty_dir), "--format", "json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"errors": 0, "warnings": 0, "path_errors": [], "findings": []}


def test_json_path_errors_live_in_payload_and_stderr_not_stdout(tmp_path, capsys):
    path = write(tmp_path, "ok.yml", "groups: []\n")
    missing = tmp_path / "absent.yml"
    assert main([str(path), str(missing), "--format", "json"]) == EXIT_USAGE
    captured = capsys.readouterr()

    payload = json.loads(captured.out)  # stdout — чистый JSON, без текстовых строк
    assert len(payload["path_errors"]) == 1
    assert "absent.yml" in payload["path_errors"][0]
    assert payload["findings"] == []

    assert captured.err.startswith("galint: ")
    assert "absent.yml" in captured.err


# --- --format text: порядок, пустая строка, итог --------------------------


def test_text_lists_errors_before_warnings(tmp_path, capsys):
    path = write(tmp_path, "mixed.yml", MIXED_YML)
    assert main([str(path)]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if " error " in line or " warning " in line]

    levels = [line.split(": ")[1].split()[0] for line in lines]
    assert levels == ["error", "warning"]  # error всегда выше warning
    assert "GAL005" in lines[0] and "GAL007" in lines[1]


def test_text_summary_is_last_line_after_blank_line(tmp_path, capsys):
    path = write(tmp_path, "mixed.yml", MIXED_YML)
    main([str(path)])
    out = capsys.readouterr().out

    assert out.endswith("\n")
    lines = out.splitlines()
    assert lines[-1] == "ошибок: 1, предупреждений: 1"
    assert lines[-2] == ""  # пустая строка между находками и итогом
    assert lines[0] != ""


def test_text_without_findings_has_no_leading_blank_line(tmp_path, capsys):
    path = write(tmp_path, "ok.yml", "groups: []\n")
    assert main([str(path)]) == EXIT_OK
    captured = capsys.readouterr()
    assert captured.out == "ошибок: 0, предупреждений: 0\n"
    assert captured.err == ""


def test_text_adds_read_error_line_after_summary(tmp_path, capsys):
    empty_dir = tmp_path / "vacant"
    empty_dir.mkdir()
    missing = tmp_path / "absent.yml"
    assert main([str(empty_dir), str(missing)]) == EXIT_USAGE
    captured = capsys.readouterr()

    lines = captured.out.splitlines()
    assert lines[0] == "ошибок: 0, предупреждений: 0"
    assert lines[1] == "файлов с ошибкой чтения: 1"
    assert len(lines) == 2  # в stdout нет строк stderr


# --- --version / --help ---------------------------------------------------


def test_version_flag_prints_banner_and_exits_zero(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "grafana_alert_lint", "--version"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )
    assert result.returncode == EXIT_OK
    assert result.stdout.strip() == f"galint {__version__}"
    assert result.stderr == ""


def test_help_lists_every_documented_flag(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "grafana_alert_lint", "--help"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )
    assert result.returncode == EXIT_OK
    assert result.stdout.startswith("usage: galint")
    for flag in (
        "--format",
        "--strict",
        "--opinionated",
        "--max-file-size",
        "--ignore",
        "--version",
        "--help",
    ):
        assert flag in result.stdout, flag


def test_no_arguments_is_usage_error(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "grafana_alert_lint"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )
    assert result.returncode == EXIT_USAGE
    assert "usage: galint" in result.stderr
    assert result.stdout == ""


# --- --ignore: регистр, пробелы, неизвестные коды -------------------------


def test_ignore_tolerates_spaces_case_and_trailing_comma(tmp_path, capsys):
    path = write(tmp_path, "err.yml", ERROR_YML)
    for value in (" GAL005 ", "gal005", "GAL005,", "GAL-999,  gal005 ,"):
        assert main([str(path), "--ignore", value]) == EXIT_OK, value
    capsys.readouterr()

    # пустое значение и неизвестные коды ничего не отбрасывают
    assert main([str(path), "--ignore", ""]) == EXIT_FINDINGS
    capsys.readouterr()
    assert main([str(path), "--ignore", "GAL999,GAL404"]) == EXIT_FINDINGS
    assert "GAL005" in capsys.readouterr().out


# --- --max-file-size: границы ---------------------------------------------


def test_max_file_size_boundaries(tmp_path, capsys):
    path = write(tmp_path, "err.yml", ERROR_YML)
    size = path.stat().st_size

    # 1 байт — любой реальный файл больше лимита
    assert main([str(path), "--max-file-size", "1"]) == EXIT_USAGE
    assert "больше лимита" in capsys.readouterr().err

    # ровно размер файла — лимит ещё не превышен
    assert main([str(path), "--max-file-size", str(size)]) == EXIT_FINDINGS
    capsys.readouterr()

    # огромный лимит — обычный прогон
    assert main([str(path), "--max-file-size", str(10**12)]) == EXIT_FINDINGS
    assert ": error GAL005" in capsys.readouterr().out

    # 0 — без лимита
    assert main([str(path), "--max-file-size", "0"]) == EXIT_FINDINGS
    assert ": error GAL005" in capsys.readouterr().out


def test_invalid_max_file_size_is_usage_error_end_to_end(tmp_path):
    """Отрицательный/нечисловой лимит — код 2 от самого процесса, без отчёта."""
    write(tmp_path, "err.yml", ERROR_YML)
    for value in ("-1", "много"):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "grafana_alert_lint",
                str(tmp_path),
                "--max-file-size",
                value,
            ],
            capture_output=True,
            text=True,
            cwd=tmp_path,
            check=False,
        )
        assert result.returncode == EXIT_USAGE, value
        assert result.stdout == ""
        assert "usage: galint" in result.stderr
        assert "Traceback" not in result.stderr


# --- разворот каталога: рекурсия, SKIP_DIRS, симлинки, дедупликация -------


def test_recursion_keeps_yaml_and_skips_skip_dirs(tmp_path, capsys):
    write(tmp_path, "a/b/c/deep.yml", ERROR_YML)
    for skip in (".git", ".venv", "venv", "node_modules", "__pycache__"):
        write(tmp_path, f"{skip}/noise.yml", ERROR_YML)
    write(tmp_path, "notes.txt", ERROR_YML)
    write(tmp_path, "rules.json", ERROR_YML)

    assert main([str(tmp_path), "--format", "json"]) == EXIT_FINDINGS
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["errors"] == 1  # только a/b/c/deep.yml
    assert payload["findings"][0]["path"].endswith("deep.yml")
    assert captured.err == ""


def test_symlink_to_file_is_linted_and_dead_symlink_is_skipped(tmp_path, capsys):
    real = write(tmp_path, "real.yml", ERROR_YML)
    (tmp_path / "link.yml").symlink_to(real)
    (tmp_path / "gone.yml").symlink_to(tmp_path / "missing.yml")

    assert main([str(tmp_path), "--format", "json"]) == EXIT_FINDINGS
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["errors"] == 1  # real.yml и link.yml — один и тот же файл
    assert payload["path_errors"] == []  # битый симлинк в обходе молчит
    assert captured.err == ""


def test_dead_symlink_argument_is_read_error_not_missing_file(tmp_path, capsys):
    (tmp_path / "gone.yml").symlink_to(tmp_path / "missing.yml")
    assert main([str(tmp_path / "gone.yml")]) == EXIT_USAGE
    captured = capsys.readouterr()
    assert "не обычный файл" in captured.err
    assert "нет такого файла" not in captured.err
    assert "ошибок: 0" in captured.out


def test_directory_file_and_repeat_lint_the_file_once(tmp_path, capsys):
    path = write(tmp_path, "rules.yml", WARN_YML)
    args = [str(tmp_path), str(path), str(path), "--format", "json"]

    assert main(args) == EXIT_OK  # одно предупреждение, без --strict
    payload = json.loads(capsys.readouterr().out)
    assert payload["warnings"] == 1  # не удвоилось
    assert all(f["code"] != "GAL007" or f["level"] == "warning" for f in payload["findings"])
    assert len({f["path"] for f in payload["findings"]}) == 1


@pytest.mark.skipif(os.geteuid() == 0, reason="root читает каталог независимо от прав")
def test_unreadable_subdirectory_is_reported_but_neighbours_linted(tmp_path, capsys):
    write(tmp_path, "ok.yml", ERROR_YML)
    locked = tmp_path / "locked"
    locked.mkdir()
    write(locked, "inside.yml", ERROR_YML)
    locked.chmod(0o000)
    try:
        assert main([str(tmp_path), "--format", "json"]) == EXIT_USAGE
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["errors"] == 1  # ok.yml прочитан и проверен
        assert len(payload["path_errors"]) == 1
        assert "locked" in payload["path_errors"][0]
        assert "locked" in captured.err
    finally:
        locked.chmod(0o755)


# --- stdout vs stderr -----------------------------------------------------


def test_findings_only_run_writes_nothing_to_stderr(tmp_path, capsys):
    path = write(tmp_path, "mixed.yml", MIXED_YML)
    assert main([str(path)]) == EXIT_FINDINGS
    captured = capsys.readouterr()
    assert "GAL005" in captured.out
    assert captured.err == ""


def test_python_dash_m_matches_cli_contract(tmp_path):
    write(tmp_path, "err.yml", ERROR_YML)

    ok = subprocess.run(
        [sys.executable, "-m", "grafana_alert_lint", str(tmp_path)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )
    assert ok.returncode == EXIT_FINDINGS
    assert "ошибок: 1, предупреждений: 0" in ok.stdout
    assert ok.stderr == ""

    broken = subprocess.run(
        [sys.executable, "-m", "grafana_alert_lint", str(tmp_path / "absent.yml")],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )
    assert broken.returncode == EXIT_USAGE
    assert "ошибок: 0" in broken.stdout  # отчёт ушёл в stdout даже при ошибке пути
    assert broken.stderr.startswith("galint: ")
    assert "galint:" not in broken.stdout
