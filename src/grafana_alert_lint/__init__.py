"""Линтер провижиненных правил алертов Grafana."""

# Единственный источник версии: pyproject.toml читает её отсюда
# (`[tool.setuptools.dynamic] version = {attr = "grafana_alert_lint.__version__"}`),
# а `publish.yml` сверяет с ней тег. Второго места с номером быть не должно.
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
