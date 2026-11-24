"""CLI: `galint <файлы или каталоги> [--format text|json] [--strict]`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .linter import Finding, LintError, LintState, lint_path

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

SUFFIXES = {".yml", ".yaml"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}


def collect_paths(targets: list[Path]) -> tuple[list[Path], list[str]]:
    """Разворачивает каталоги в список YAML-файлов, собирая ошибки чтения."""
    files: list[Path] = []
    errors: list[str] = []
    for target in targets:
        if target.is_dir():
            for candidate in sorted(target.rglob("*")):
                if candidate.suffix.lower() not in SUFFIXES:
                    continue
                if SKIP_DIRS & set(candidate.parts):
                    continue
                files.append(candidate)
        elif target.is_file():
            files.append(target)
        else:
            errors.append(f"{target}: нет такого файла или каталога")
    return files, errors


def render_text(findings: list[Finding], path_errors: list[str] | None = None) -> str:
    order = {"error": 0, "warning": 1}
    ordered = sorted(findings, key=lambda f: (order.get(f.level, 9), f.path, f.group, f.rule))
    lines = [str(finding) for finding in ordered]
    if lines:
        lines.append("")
    errors = sum(1 for f in findings if f.level == "error")
    warnings = sum(1 for f in findings if f.level == "warning")
    lines.append(f"ошибок: {errors}, предупреждений: {warnings}")
    if path_errors:
        lines.append(f"файлов с ошибкой чтения: {len(path_errors)}")
    return "\n".join(lines)


def render_json(findings: list[Finding], path_errors: list[str] | None = None) -> str:
    return json.dumps(
        {
            "errors": sum(1 for f in findings if f.level == "error"),
            "warnings": sum(1 for f in findings if f.level == "warning"),
            "path_errors": path_errors or [],
            "findings": [finding.as_dict() for finding in findings],
        },
        ensure_ascii=False,
        indent=2,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="galint",
        description="Линтер провижиненных правил алертов Grafana",
        epilog="Коды проверок описаны в README и в docstring модуля grafana_alert_lint.linter.",
    )
    parser.add_argument("paths", nargs="+", type=Path, help="файлы или каталоги с правилами Grafana")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="вид отчёта")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="предупреждения считать ошибками (для CI на новом репозитории)",
    )
    parser.add_argument("--version", action="version", version=f"galint {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Возвращает код выхода. `--help`/`--version` обрабатывает argparse сам."""
    args = build_parser().parse_args(argv)
    files, path_errors = collect_paths(args.paths)

    findings: list[Finding] = []
    state = LintState()  # уникальность uid/title — на весь запуск, а не на файл
    for path in files:
        try:
            findings.extend(lint_path(path, state=state))
        except LintError as exc:
            path_errors.append(str(exc))

    if args.format == "json":
        print(render_json(findings, path_errors))
    else:
        print(render_text(findings, path_errors))

    for message in path_errors:
        print(f"galint: {message}", file=sys.stderr)

    if path_errors:
        return EXIT_USAGE
    errors = sum(1 for f in findings if f.level == "error")
    warnings = sum(1 for f in findings if f.level == "warning")
    if errors or (args.strict and warnings):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
