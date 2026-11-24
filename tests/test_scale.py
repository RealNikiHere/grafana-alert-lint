"""Тема t7: масштаб, лимиты и устойчивость на больших/глубоких входах.

Ничего не дублирует из tests/: там проверяются семантика проверок, коды,
дедупликация путей и одиночные случаи лимита. Здесь — границы лимита
размера, большие провижининги, глубина YAML, длинные выражения, детерминизм
и число чтений файла CLI.

Пороги времени намеренно щедрые (во много раз больше измеренного), чтобы
тесты не флакали на медленной машине в CI.
"""

from __future__ import annotations

import time
import tracemalloc
from pathlib import Path

import pytest

from grafana_alert_lint.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main
from grafana_alert_lint.linter import (
    DEFAULT_MAX_FILE_BYTES,
    LintError,
    LintState,
    lint_document,
    lint_path,
)

# Таймауты: измеренные значения в разы меньше (см. отчёт), запас — на слабый CI.
TIME_5000_RULES = 10.0
TIME_BIG_FILE = 15.0
TIME_GENERIC = 10.0


def _rule_yaml(index: int, *, annotation: str = "ok", indent: int = 6) -> str:
    """Одно правило в YAML-тексте, по умолчанию без находок."""
    pad = " " * indent
    field = " " * (indent + 2)
    return (
        f"{pad}- uid: u{index}\n"
        f"{field}title: r{index}\n"
        f"{field}condition: A\n"
        f"{field}for: 5m\n"
        f"{field}noDataState: OK\n"
        f"{field}execErrState: OK\n"
        f"{field}labels: {{severity: x}}\n"
        f"{field}annotations: {{summary: '{annotation}'}}\n"
        f"{field}data: [{{refId: A, model: {{expr: up, refId: A}}}}]\n"
    )


def _group_yaml(rules: list[str], *, name: str = "g", interval: str = "1m") -> str:
    return f"groups:\n  - name: {name}\n    interval: {interval}\n    rules:\n" + "".join(rules)


def _clean_rule_dict(index: int) -> dict:
    return {
        "uid": f"u{index}",
        "title": f"t{index}",
        "condition": "A",
        "for": "5m",
        "noDataState": "OK",
        "execErrState": "OK",
        "labels": {"severity": "x"},
        "annotations": {"summary": "s"},
        "data": [{"refId": "A", "model": {"expr": "up", "refId": "A"}}],
    }


# --- границы лимита размера файла ---------------------------------------


def test_max_bytes_equal_to_file_size_is_allowed(tmp_path):
    """Ровно max_bytes — файл проходит: лимит сравнивается с `size > max_bytes`."""
    path = tmp_path / "rules.yml"
    path.write_text(_group_yaml([_rule_yaml(0)]), encoding="utf-8")
    size = path.stat().st_size

    assert lint_path(path, max_bytes=size) == []


def test_max_bytes_one_byte_under_file_size_is_rejected(tmp_path):
    """Файл на байт больше лимита — ошибка чтения, а не «чисто»."""
    path = tmp_path / "rules.yml"
    path.write_text(_group_yaml([_rule_yaml(0)]), encoding="utf-8")
    size = path.stat().st_size

    with pytest.raises(LintError) as excinfo:
        lint_path(path, max_bytes=size - 1)

    message = str(excinfo.value)
    assert "больше лимита" in message
    assert str(size) in message  # реальный размер назван, а не округлён


def test_max_bytes_zero_means_no_limit(tmp_path):
    """`0` снимает лимит: файл больше дефолтных 4 МиБ линтуется, а не отвергается."""
    path = tmp_path / "big.yml"
    path.write_text(
        "groups: []\n" + "# padding\n" * ((DEFAULT_MAX_FILE_BYTES + 64) // 10),
        encoding="utf-8",
    )
    assert path.stat().st_size > DEFAULT_MAX_FILE_BYTES

    # Контроль: по умолчанию тот же файл — ошибка чтения.
    with pytest.raises(LintError):
        lint_path(path)

    start = time.monotonic()
    findings = lint_path(path, max_bytes=0)
    elapsed = time.monotonic() - start

    assert findings == []
    assert elapsed < TIME_BIG_FILE


def test_max_bytes_none_means_no_limit(tmp_path):
    """`None` — тоже «без лимита», а не «лимит по умолчанию»."""
    path = tmp_path / "big.yml"
    path.write_text(
        "groups: []\n" + "# padding\n" * ((DEFAULT_MAX_FILE_BYTES + 64) // 10),
        encoding="utf-8",
    )

    assert lint_path(path, max_bytes=None) == []


# --- большие провижининги ------------------------------------------------


def test_5000_rules_are_linted_quickly_and_counted_exactly(tmp_path):
    """5000 правил: ровно 2500 находок GAL005 и заметно меньше 10 секунд."""
    rules = [_rule_yaml(i, annotation="a < b" if i % 2 == 0 else "ok") for i in range(5000)]
    path = tmp_path / "many.yml"
    path.write_text(_group_yaml(rules), encoding="utf-8")

    start = time.monotonic()
    findings = lint_path(path)
    elapsed = time.monotonic() - start

    assert len(findings) == 2500
    assert {finding.code for finding in findings} == {"GAL005"}
    assert {finding.rule for finding in findings} == {f"r{i}" for i in range(0, 5000, 2)}
    assert elapsed < TIME_5000_RULES, f"5000 правил линтуются {elapsed:.1f}s"


def test_200_documents_in_one_file(tmp_path):
    """200 документов через `---`: все разобраны, uid накоплены, находок нет."""
    docs = [
        _group_yaml([_rule_yaml(i).replace(f"uid: u{i}", f"uid: d{i}")], name=f"g{i}")
        for i in range(200)
    ]
    path = tmp_path / "multi.yml"
    path.write_text("---\n".join(docs), encoding="utf-8")

    state = LintState()
    start = time.monotonic()
    findings = lint_path(path, state=state)
    elapsed = time.monotonic() - start

    assert findings == []
    assert len(state.uids) == 200
    assert len(state.titles) == 200
    assert {org for org, _ in state.uids} == {"1"}
    assert {org for org, _, _ in state.titles} == {"1"}
    assert elapsed < TIME_GENERIC


def test_duplicates_across_200_documents_are_all_reported(tmp_path):
    """Один и тот же uid в 200 документах: 199 находок GAL007, а не одна."""
    doc = _group_yaml([_rule_yaml(0)])
    path = tmp_path / "dup.yml"
    path.write_text("---\n".join([doc] * 200), encoding="utf-8")

    findings = lint_path(path)

    # Каждый повторный документ: дубль uid (error) + дубль title (warning).
    assert [finding.code for finding in findings] == ["GAL007"] * (2 * 199)
    assert [finding.level for finding in findings] == ["error", "warning"] * 199


def test_1000_level_nested_yaml_is_a_read_error_not_a_traceback(tmp_path, capsys):
    """Глубина 1000 вложенных списков: LintError, а не RecursionError/трейсбек."""
    path = tmp_path / "deep.yml"
    path.write_text("[" * 1000 + "]" * 1000, encoding="utf-8")

    with pytest.raises(LintError) as excinfo:
        lint_path(path)

    # Именно ошибка чтения YAML: трейсбек наружу не выходит.
    assert not isinstance(excinfo.value, RecursionError)
    assert "YAML не разбирается" in str(excinfo.value)

    assert main([str(path)]) == EXIT_USAGE
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert "YAML не разбирается" in captured.err


# --- длинные выражения и много аннотаций --------------------------------


def test_100kb_promql_expression_is_linted_correctly():
    """Выражение ~100 КБ: сравнение находится (GAL001), а не теряется/зависает."""
    long_expr = " + ".join(['up{job="a"}'] * 7000) + " == 0"
    assert len(long_expr) >= 95_000

    rule = _clean_rule_dict(0)
    rule["noDataState"] = "Alerting"
    rule["data"] = [{"refId": "A", "model": {"expr": long_expr, "refId": "A"}}]

    start = time.monotonic()
    findings = lint_document({"groups": [{"name": "g", "interval": "1m", "rules": [rule]}]})
    elapsed = time.monotonic() - start

    assert [finding.code for finding in findings] == ["GAL001"]
    assert elapsed < TIME_GENERIC, f"100 КБ PromQL линтуется {elapsed:.1f}s"


def test_100kb_promql_with_comparison_only_inside_string_is_not_gal001():
    """Сравнение внутри строкового литерала в 100 КБ выражения — не фильтр."""
    long_expr = ", ".join(['x="a == b"'] * 10_000)
    expr = "{" + long_expr + "}"
    assert len(expr) >= 95_000

    rule = _clean_rule_dict(0)
    rule["noDataState"] = "Alerting"
    rule["data"] = [{"refId": "A", "model": {"expr": expr, "refId": "A"}}]

    start = time.monotonic()
    findings = lint_document({"groups": [{"name": "g", "interval": "1m", "rules": [rule]}]})
    elapsed = time.monotonic() - start

    assert findings == []
    assert elapsed < TIME_GENERIC


def test_many_annotations_are_all_scanned(tmp_path):
    """5000 аннотаций: каждая с '<' даёт GAL005, остальные молчат."""
    annotations = "".join(
        f"          ann{i}: {'bad < value' if i % 1000 == 0 else 'fine'}\n" for i in range(5000)
    )
    path = tmp_path / "ann.yml"
    path.write_text(
        "groups:\n"
        "  - name: g\n"
        "    interval: 1m\n"
        "    rules:\n"
        "      - uid: u\n"
        "        title: t\n"
        "        condition: A\n"
        "        for: 5m\n"
        "        noDataState: OK\n"
        "        execErrState: OK\n"
        "        labels: {severity: x}\n"
        "        annotations:\n"
        "          summary: s\n" + annotations + "        data: [{refId: A, model: {expr: up}}]\n",
        encoding="utf-8",
    )

    start = time.monotonic()
    findings = lint_path(path)
    elapsed = time.monotonic() - start

    assert [finding.code for finding in findings] == ["GAL005"] * 5
    assert {finding.message.split(":")[0] for finding in findings} == {
        f"'<' в annotations.ann{i}" for i in range(0, 5000, 1000)
    }
    assert elapsed < TIME_GENERIC


# --- детерминизм ---------------------------------------------------------


def test_findings_are_deterministic_across_runs(tmp_path, capsys):
    """Два прогона на одном файле: тот же список, тот же порядок — в API и в CLI."""
    rules = [
        _rule_yaml(0, annotation="a < b"),
        _rule_yaml(0, annotation="c < d"),  # дубль uid и title
        _rule_yaml(3),
    ]
    path = tmp_path / "det.yml"
    path.write_text(_group_yaml(rules) + "---\n" + _group_yaml([_rule_yaml(3)]), encoding="utf-8")

    first = [finding.as_dict() for finding in lint_path(path)]
    second = [finding.as_dict() for finding in lint_path(path)]

    assert first == second  # включает порядок
    assert len(first) >= 3

    assert main([str(path), "--format", "json"]) == EXIT_FINDINGS
    cli_first = capsys.readouterr().out
    assert main([str(path), "--format", "json"]) == EXIT_FINDINGS
    cli_second = capsys.readouterr().out
    assert cli_first == cli_second


def test_lint_state_with_50000_uids_works_and_stays_small():
    """50 000 uid: состояние накапливает все ключи, дубли ловит, память разумна."""
    rules = [_clean_rule_dict(i) for i in range(50_000)]
    doc = {"groups": [{"name": "g", "interval": "1m", "rules": rules}]}

    state = LintState()
    tracemalloc.start()
    start = time.monotonic()
    findings = lint_document(doc, state=state)
    elapsed = time.monotonic() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert findings == []
    assert len(state.uids) == 50_000
    assert len(state.titles) == 50_000
    assert peak < 100 * 1024 * 1024, f"пик памяти {peak / 1e6:.1f} МБ"
    assert elapsed < TIME_GENERIC, f"50 000 правил линтуются {elapsed:.1f}s"

    # На масштабе дедупликация всё ещё работает.
    assert ("1", "u49999") in state.uids
    dup = lint_document(doc, state=state)
    # По два дубля на правило: uid (error) и title (warning).
    assert len(dup) == 2 * 50_000
    assert {finding.code for finding in dup} == {"GAL007"}


# --- CLI: файл читается один раз ----------------------------------------


def _count_read_text(monkeypatch) -> list[str]:
    calls: list[str] = []
    original = Path.read_text

    def counting(self, *args, **kwargs):
        calls.append(str(self))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", counting)
    return calls


def test_cli_reads_each_file_exactly_once(tmp_path, capsys, monkeypatch):
    """Один файл — одно чтение; 150 файлов — 150 чтений, без перечитываний."""
    single = tmp_path / "single.yml"
    single.write_text(_group_yaml([_rule_yaml(0)]), encoding="utf-8")
    many = tmp_path / "many"
    many.mkdir()
    for i in range(150):
        (many / f"g{i:03d}.yml").write_text(_group_yaml([_rule_yaml(i)]), encoding="utf-8")
    calls = _count_read_text(monkeypatch)

    assert main([str(single)]) == EXIT_OK
    capsys.readouterr()
    assert calls.count(str(single)) == 1

    calls.clear()
    assert main([str(many)]) == EXIT_OK
    capsys.readouterr()
    assert len(calls) == 150
    assert len(set(calls)) == 150
