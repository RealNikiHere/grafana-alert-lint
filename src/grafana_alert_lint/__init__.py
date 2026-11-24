"""Линтер провижиненных правил алертов Grafana."""

__version__ = "0.1.0"

from .linter import Finding, lint_document, lint_path

__all__ = ["Finding", "__version__", "lint_document", "lint_path"]
