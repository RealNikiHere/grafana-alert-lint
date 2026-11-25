"""Публичный API, версия и упаковка `grafana-alert-lint`.

Что здесь проверяется (и чего нет в `tests/`):

* `__all__` — состав, отсутствие дублей, импортируемость каждого имени,
  `from grafana_alert_lint import *`;
* сигнатуры `lint_document` / `lint_path` / `lint_rule`: `opinionated` по
  умолчанию `False`, служебные параметры — только по имени;
* версия — один источник: `__version__` == метаданные *установленного*
  пакета == динамическое поле `pyproject.toml` == верхний раздел CHANGELOG;
* `python -m grafana_alert_lint` печатает `galint <версия>` и линтует;
* console script `galint` объявлен в метаданных и указывает на `cli:main`;
* пример из README воспроизводится дословно (regression-0003 → код 1 и
  GAL001, clean.yml → код 0), а все флаги из блока «Использование» реально
  есть в `--help`;
* документированные коды GAL001..GAL013 (README + docstring модуля) в точности
  совпадают с реально выдаваемыми, включая уровни и пометку «вкусовая» (`†`);
* упаковка: `MANIFEST.in` покрывает CHANGELOG и tests, метаданные wheel и
  содержимое sdist (если `dist/` есть).

Тесты самодостаточны: правило для проверки кодов строится локально, ничего не
импортируется из `tests/`.
"""

from __future__ import annotations

import importlib
import importlib.metadata as md
import inspect
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

import grafana_alert_lint
from grafana_alert_lint import cli as cli_module
from grafana_alert_lint import linter
from grafana_alert_lint.linter import lint_document

DIST_NAME = "grafana-alert-lint"


def _repo_root() -> Path:
    """Каталог репозитория: ищем вверх от этого файла до `pyproject.toml`."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file():
            return parent
    raise RuntimeError(f"не нашли pyproject.toml выше {here}")


ROOT = _repo_root()
README = ROOT / "README.md"
PYPROJECT = ROOT / "pyproject.toml"
MANIFEST = ROOT / "MANIFEST.in"
CHANGELOG = ROOT / "CHANGELOG.md"
FIXTURES = ROOT / "tests" / "fixtures"
DIST = ROOT / "dist"

ALL_CODES = {f"GAL{number:03d}" for number in range(1, 14)}


# --- helpers ---------------------------------------------------------------


def build_rule(**overrides):
    """Правило, валидное во всех прочих отношениях."""
    rule = {
        "uid": "r1",
        "title": "Правило",
        "condition": "A",
        "for": "5m",
        "noDataState": "OK",
        "execErrState": "Error",
        "labels": {"severity": "warning"},
        "annotations": {"summary": "Свободно меньше 10 процентов"},
        "data": [{"refId": "A", "model": {"expr": "up", "refId": "A"}}],
    }
    rule.update(overrides)
    return rule


def document_with_all_codes() -> dict:
    """Один документ, в котором дают находку все коды GAL001..GAL013."""
    group_one = {
        "name": "g1",
        "interval": "1m",
        "rules": [
            # GAL001: Alerting + фильтрующее сравнение
            build_rule(
                uid="g1",
                title="GAL001",
                noDataState="Alerting",
                data=[{"refId": "A", "model": {"expr": "up == 0", "refId": "A"}}],
            ),
            # GAL002: NoData
            build_rule(uid="g2", title="GAL002", noDataState="NoData"),
            # GAL003: noDataState отсутствует
            {
                key: value
                for key, value in build_rule(uid="g3", title="GAL003").items()
                if key != "noDataState"
            },
            # GAL004: нет `for`
            {
                key: value
                for key, value in build_rule(uid="g4", title="GAL004").items()
                if key != "for"
            },
            # GAL005: `<` в тексте аннотации
            build_rule(uid="g5", title="GAL005", annotations={"summary": "диск < 10%"}),
            # GAL006: condition ссылается на отсутствующий refId
            build_rule(uid="g6", title="GAL006", condition="Z"),
            # GAL007 (error): повторяющийся uid
            build_rule(uid="dup", title="Первый дубль uid"),
            build_rule(uid="dup", title="Второй дубль uid"),
            # GAL007 (warning): повторяющийся title в папке
            build_rule(uid="g7a", title="Дубль заголовка"),
            build_rule(uid="g7b", title="Дубль заголовка"),
            # GAL008: нет labels.severity
            build_rule(uid="g8", title="GAL008", labels={"component": "node"}),
            # GAL009: нет annotations.summary
            build_rule(uid="g9", title="GAL009", annotations={"description": "без сути"}),
            # GAL010: нет execErrState
            {
                key: value
                for key, value in build_rule(uid="g10", title="GAL010").items()
                if key != "execErrState"
            },
            # GAL011: for короче интервала группы
            build_rule(uid="g11", title="GAL011", **{"for": "10s"}),
            # GAL012: ни uid, ни title
            {
                key: value
                for key, value in build_rule(uid="g12", title="GAL012").items()
                if key not in {"uid", "title"}
            },
        ],
    }
    # GAL013: interval группы не разбирается как длительность Grafana
    group_two = {"name": "g2", "interval": "1.5s", "rules": [build_rule(uid="g13", title="GAL013")]}
    return {"groups": [group_one, group_two]}


def codes_of(findings) -> set[str]:
    return {finding.code for finding in findings}


def readme_text() -> str:
    return README.read_text(encoding="utf-8")


def readme_usage_block() -> str:
    """Первый ```bash-блок раздела про использование (README есть на двух языках)."""
    match = re.search(r"^## (?:Usage|Использование)\s*\n+```bash\n(.*?)```", readme_text(), re.S | re.M)
    assert match, "в README нет раздела Usage/Использование с ```bash-блоком"
    return match.group(1)


def readme_console_example() -> tuple[str, list[str]]:
    """(команда, напечатанные строки) из первого ```console-блока README."""
    text = readme_text()
    block = text.split("```console\n", 1)[1].split("```", 1)[0]
    lines = block.splitlines()
    assert lines[0].startswith("$ "), lines[0]
    command = lines[0][2:].strip()
    expected = [line for line in lines[1:] if line.strip()]
    return command, expected


def readme_code_table() -> dict[str, set[str]]:
    """Код проверки → множество документированных уровней (README-таблица)."""
    documented: dict[str, set[str]] = {}
    for line in readme_text().splitlines():
        match = re.match(r"^\|\s*(GAL\d{3})\s*\|\s*(error|warning)(\s*†)?\s*\|", line)
        if match:
            documented.setdefault(match.group(1), set()).add(match.group(2))
    return documented


def readme_dagger_codes() -> set[str]:
    """Коды, помеченные в README как «вкусовые» (†)."""
    marked: set[str] = set()
    for line in readme_text().splitlines():
        match = re.match(r"^\|\s*(GAL\d{3})\s*\|\s*(error|warning)(\s*†)\s*\|", line)
        if match:
            marked.add(match.group(1))
    return marked


def source_emitted_codes() -> set[str]:
    """Коды, которые код линтера вообще способен выдать (литералы в вызовах)."""
    text = (ROOT / "src" / "grafana_alert_lint" / "linter.py").read_text(encoding="utf-8")
    return set(re.findall(r"[\"'](GAL\d{3})[\"']", text))


def subprocess_env() -> dict[str, str]:
    import os

    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return env


def run_module(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "grafana_alert_lint", *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(cwd) if cwd is not None else None,
        env=subprocess_env(),
    )


# --- публичный API ---------------------------------------------------------


def test_all_names_exist_and_are_unique():
    exported = grafana_alert_lint.__all__
    assert isinstance(exported, list)
    assert len(exported) == len(set(exported)), "в __all__ есть дубли"
    for name in exported:
        assert hasattr(grafana_alert_lint, name), f"{name} из __all__ нет в модуле"
        assert not name.startswith("_") or name == "__version__", name


def test_star_import_exposes_exactly_all():
    namespace: dict[str, object] = {}
    exec("from grafana_alert_lint import *", namespace)  # noqa: S102 — проверяем сам __all__
    imported = {name for name in namespace if name != "__builtins__"}
    assert imported == set(grafana_alert_lint.__all__)


def test_public_api_surface_is_stable():
    assert set(grafana_alert_lint.__all__) == {
        "Finding",
        "LintState",
        "__version__",
        "is_filtering_expression",
        "lint_document",
        "lint_path",
    }
    # `lint_rule` — публичная функция подмодуля, но не часть высокоуровневого
    # API: ей нужны path/group/index от вызывающего.
    assert callable(linter.lint_rule)
    assert "lint_rule" not in grafana_alert_lint.__all__


def test_finding_and_lint_state_are_the_exported_objects():
    assert grafana_alert_lint.Finding is linter.Finding
    assert grafana_alert_lint.LintState is linter.LintState
    finding = grafana_alert_lint.Finding("GAL001", "error", "p.yml", "g", "r", "m")
    assert finding.as_dict()["code"] == "GAL001"
    assert isinstance(grafana_alert_lint.LintState(), grafana_alert_lint.LintState)


# --- сигнатуры -------------------------------------------------------------


def test_lint_document_signature_is_keyword_only_and_quiet_by_default():
    params = inspect.signature(lint_document).parameters
    assert list(params) == ["doc", "path", "state", "opinionated"]
    assert params["doc"].default is inspect.Parameter.empty
    assert params["path"].default == "<memory>", "path должен иметь дефолт для lint в памяти"
    assert params["state"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["opinionated"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["opinionated"].default is False


def test_lint_path_signature_is_keyword_only_and_quiet_by_default():
    params = inspect.signature(linter.lint_path).parameters
    assert list(params) == ["path", "state", "max_bytes", "opinionated"]
    for name in ("state", "max_bytes", "opinionated"):
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY, name
    assert params["state"].default is None
    assert params["max_bytes"].default == 4 * 1024 * 1024
    assert params["max_bytes"].default == linter.DEFAULT_MAX_FILE_BYTES
    assert params["opinionated"].default is False


def test_lint_rule_signature_is_keyword_only_and_quiet_by_default():
    params = inspect.signature(linter.lint_rule).parameters
    assert list(params) == ["rule", "path", "group", "index", "group_interval", "opinionated"]
    assert params["rule"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    for name in ("path", "group", "index", "group_interval"):
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY, name
        assert params[name].default is inspect.Parameter.empty, f"{name} обязан указываться"
    assert params["opinionated"].default is False


def test_second_positional_argument_expression_is_rejected():
    """`lint_document(doc, path, state)` — типичная ошибка: state не позиционный."""
    with pytest.raises(TypeError):
        lint_document({}, "p.yml", linter.LintState())  # type: ignore[misc]


def test_opinionated_default_keeps_style_findings_silent():
    doc = {
        "groups": [
            {
                "name": "g",
                "interval": "1m",
                "rules": [
                    build_rule(
                        uid="quiet",
                        title="Тихий",
                        noDataState="NoData",  # GAL002 — вкусовая
                        labels={},  # GAL008
                        annotations={},  # GAL009
                        **{"for": "10s"},  # GAL011
                    )
                ],
            }
        ]
    }
    quiet = codes_of(lint_document(doc))
    loud = codes_of(lint_document(doc, opinionated=True))
    assert quiet == set(), f"без opinionated вкусовые проверки должны молчать: {quiet}"
    assert {"GAL002", "GAL008", "GAL009", "GAL011"} <= loud


# --- версия ----------------------------------------------------------------


def test_version_matches_installed_metadata():
    installed = md.version(DIST_NAME)
    assert grafana_alert_lint.__version__ == installed
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:[-.+][0-9A-Za-z.\-]+)?", grafana_alert_lint.__version__)


def test_version_is_single_source_in_pyproject():
    text = PYPROJECT.read_text(encoding="utf-8")
    assert 'dynamic = ["version"]' in text, "версия должна быть dynamic"
    assert not re.search(r"^version\s*=\s*[\"']", text, re.MULTILINE), (
        "статической версии быть не должно"
    )
    assert 'version = {attr = "grafana_alert_lint.__version__"}' in text
    # attr, на который ссылается pyproject, действительно даёт нашу версию
    module, _, attribute = "grafana_alert_lint.__version__".rpartition(".")
    assert getattr(importlib.import_module(module), attribute) == grafana_alert_lint.__version__


def test_changelog_top_section_matches_version():
    first = next(
        line
        for line in CHANGELOG.read_text(encoding="utf-8").splitlines()
        if line.startswith("## ")
    )
    assert f"[{grafana_alert_lint.__version__}]" in first, first


def test_python_dash_m_prints_version_from_foreign_cwd(tmp_path):
    result = run_module(["--version"], cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"galint {grafana_alert_lint.__version__}"
    assert "Traceback" not in result.stderr


def test_python_dash_m_lints_and_returns_findings_code(tmp_path):
    target = tmp_path / "rules.yml"
    target.write_text(
        FIXTURES.joinpath("regression-0003.yml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    result = run_module([str(target)], cwd=tmp_path)
    assert result.returncode == 1, result.stderr
    assert "GAL001" in result.stdout
    assert "ошибок: 1" in result.stdout


# --- entry point -----------------------------------------------------------


def test_console_script_entry_point_is_declared():
    console = {
        entry.name: entry
        for entry in md.distribution(DIST_NAME).entry_points
        if entry.group == "console_scripts"
    }
    assert "galint" in console, sorted(console)
    assert console["galint"].value == "grafana_alert_lint.cli:main"
    assert console["galint"].load() is cli_module.main


def test_galint_script_next_to_interpreter_runs():
    script = Path(sys.executable).with_name("galint")
    if not script.is_file():
        script = shutil.which("galint") and Path(shutil.which("galint"))
    if not script:
        pytest.skip("console script galint не установлен рядом с интерпретатором")
    result = subprocess.run([str(script), "--version"], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert grafana_alert_lint.__version__ in result.stdout


# --- README: воспроизводимость и флаги -------------------------------------


def test_readme_example_is_reproduced_verbatim():
    command, expected = readme_console_example()
    assert command.split()[0] == "galint"
    assert "regression-0003.yml" in command
    result = subprocess.run(
        [sys.executable, "-m", "grafana_alert_lint", *command.split()[1:]],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(ROOT),
        env=subprocess_env(),
    )
    assert result.returncode == 1, result.stderr
    for line in expected:
        assert line in result.stdout, f"в выводе нет строки README: {line!r}\n{result.stdout}"


def test_readme_clean_fixture_exits_zero():
    result = run_module(["tests/fixtures/clean.yml"], cwd=ROOT)
    assert result.returncode == 0, result.stderr
    assert "ошибок: 0" in result.stdout


def test_readme_usage_flags_exist_in_help():
    flags = set(re.findall(r"--[a-z][a-z-]+", readme_usage_block()))
    assert flags, "в блоке «Использование» не нашлось ни одного флага"
    assert "--format" in flags and "--opinionated" in flags
    help_text = cli_module.build_parser().format_help()
    for flag in sorted(flags):
        assert flag in help_text, f"флаг {flag} из README отсутствует в --help"
    # и argparse их правда принимает
    for flag in sorted(flags):
        assert flag in run_module(["--help"]).stdout


# --- коды GAL001..GAL013 ---------------------------------------------------


def test_documented_codes_are_exactly_the_emitted_ones():
    documented = set(readme_code_table())
    assert documented == ALL_CODES, sorted(ALL_CODES - documented)
    docstring_codes = set(re.findall(r"^(GAL\d{3})\s", inspect.getdoc(linter) or "", re.MULTILINE))
    assert docstring_codes == ALL_CODES, sorted(ALL_CODES - docstring_codes)
    assert source_emitted_codes() == ALL_CODES


def test_every_documented_code_can_actually_be_raised():
    findings = lint_document(document_with_all_codes(), "doc.yml", opinionated=True)
    assert codes_of(findings) == ALL_CODES, sorted(ALL_CODES - codes_of(findings))


def test_levels_match_readme_table():
    findings = lint_document(document_with_all_codes(), "doc.yml", opinionated=True)
    produced: dict[str, set[str]] = {}
    for finding in findings:
        produced.setdefault(finding.code, set()).add(finding.level)
    assert produced == readme_code_table()


def test_style_checks_match_readme_dagger_marks():
    assert linter.STYLE_CHECKS == readme_dagger_codes()
    assert linter.STYLE_CHECKS <= ALL_CODES


# --- упаковка --------------------------------------------------------------


def test_manifest_covers_changelog_and_tests():
    lines = {
        line.strip()
        for line in MANIFEST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    assert "include CHANGELOG.md" in lines
    assert "include LICENSE" in lines
    assert "graft tests" in lines, "тесты должны попадать в sdist"
    assert "global-exclude *.py[cod]" in lines


pyproject_text = PYPROJECT.read_text(encoding="utf-8")


def test_pyproject_ships_readme_and_license():
    assert 'readme = "README.md"' in pyproject_text
    assert 'license = "Apache-2.0"' in pyproject_text
    assert 'requires-python = ">=3.10"' in pyproject_text
    assert 'galint = "grafana_alert_lint.cli:main"' in pyproject_text


def test_wheel_metadata_is_consistent():
    wheel = next(iter(sorted(DIST.glob("*.whl"))), None)
    if wheel is None:
        pytest.skip("dist/ пуст — wheel не собран")
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        raw = archive.read(metadata_name).decode("utf-8")
        fields: dict[str, list[str]] = {}
        for line in raw.splitlines():
            if not line.strip():
                break  # заголовки кончились, дальше README
            key, _, value = line.partition(": ")
            fields.setdefault(key, []).append(value)
        names = set(archive.namelist())
    assert fields["Name"] == [DIST_NAME]
    assert fields["Version"] == [grafana_alert_lint.__version__]
    assert fields["License-Expression"] == ["Apache-2.0"]
    assert fields["Requires-Python"] == [">=3.10"]
    assert any(name.endswith(".dist-info/entry_points.txt") for name in names)
    for module in ("__init__.py", "__main__.py", "cli.py", "linter.py"):
        assert f"grafana_alert_lint/{module}" in names


def test_sdist_ships_tests_and_changelog():
    sdist = next(iter(sorted(DIST.glob("*.tar.gz"))), None)
    if sdist is None:
        pytest.skip("dist/ пуст — sdist не собран")
    with tarfile.open(sdist) as archive:
        names = archive.getnames()
    assert any(name.endswith("/CHANGELOG.md") for name in names)
    assert any(name.endswith("/LICENSE") for name in names)
    assert any("/tests/test_linter.py" in name for name in names)
    assert any(name.endswith("/tests/fixtures/clean.yml") for name in names)
    assert not any("__pycache__" in name for name in names)
