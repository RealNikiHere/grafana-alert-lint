"""Линтер провижиненных правил алертов Grafana."""

__version__ = "0.1.0"

from .linter import Finding, LintState, is_filtering_expression, lint_document, lint_path

__all__ = [
    "Finding",
    "LintState",
    "__version__",
    "is_filtering_expression",
    "lint_document",
    "lint_path",
]
