"""GAL007: границы уникальности `uid` (orgId) и `title` (orgId, folder).

Матрица orgId × folder, склейка состояния между документами/файлами/CLI,
уровни и текст сообщений. Существующие тесты `tests/` покрывают базовые
случаи (1 vs 2, 1.0 vs 1, A/B папки, дубль title в двух группах), здесь —
нормализация «странных» значений, поведение накопительного `LintState` и
CLI-контракт для предупреждения.

Все тесты фиксируют текущее поведение линтера: код не менялся.
"""

from __future__ import annotations

import json

import pytest
import yaml

from grafana_alert_lint.cli import EXIT_FINDINGS, EXIT_OK, main
from grafana_alert_lint.linter import LintState, lint_document, lint_path

# --- строители документов -------------------------------------------------


def rule(uid="r1", title="Правило", **overrides):
    """Валидное по прочим проверкам правило: единственный шум — GAL007."""
    base = {
        "uid": uid,
        "title": title,
        "condition": "B",
        "for": "5m",
        "noDataState": "OK",
        "execErrState": "Error",
        "labels": {"severity": "warning"},
        "annotations": {"summary": "свободно меньше 10 процентов"},
        "data": [
            {"refId": "A", "model": {"expr": "up", "refId": "A"}},
            {"refId": "B", "model": {"type": "threshold", "expression": "A", "refId": "B"}},
        ],
    }
    base.update(overrides)
    return base


ABSENT = object()


def group(rules, *, name="g", org_id=ABSENT, folder=ABSENT, **extra):
    """Группа правил; `org_id`/`folder` не заданы, если передан ABSENT."""
    node = {"name": name, "interval": "1m", "rules": list(rules)}
    if org_id is not ABSENT:
        node["orgId"] = org_id
    if folder is not ABSENT:
        node["folder"] = folder
    node.update(extra)
    return node


def doc(*groups):
    return {"groups": list(groups)}


def dump(*groups) -> str:
    return yaml.safe_dump(doc(*groups), allow_unicode=True)


def findings_for(*groups, state=None):
    return lint_document(doc(*groups), state=state)


def gal007(*groups, state=None):
    return [f for f in findings_for(*groups, state=state) if f.code == "GAL007"]


def pairs(found):
    return [(f.code, f.level) for f in found]


# --- orgId: представление одной и той же организации ----------------------


def test_org_id_string_and_int_are_the_same_org_for_uid():
    # `orgId: "1"` (строка из шаблона) и `orgId: 1` — одна организация.
    found = gal007(
        group([rule(uid="dup", title="A")], org_id="1"),
        group([rule(uid="dup", title="B")], org_id=1),
    )
    assert pairs(found) == [("GAL007", "error")]
    assert "orgId=1" in found[0].message


def test_org_id_absent_collides_with_explicit_one_for_uid():
    # Группа без orgId — та же организация 1, что и `orgId: 1`; и две группы
    # без orgId — тоже одна организация.
    with_explicit = gal007(
        group([rule(uid="dup", title="A")]),
        group([rule(uid="dup", title="B")], org_id=1),
    )
    assert pairs(with_explicit) == [("GAL007", "error")]
    both_absent = gal007(
        group([rule(uid="dup", title="A")]),
        group([rule(uid="dup", title="B")], name="g2"),
    )
    assert pairs(both_absent) == [("GAL007", "error")]


@pytest.mark.parametrize("org_id", [1.0, "1", 1, None, True, {"bad": "value"}, ["1"]])
def test_all_degenerate_org_ids_fall_back_to_org_one(org_id):
    # `1.0`, `"1"`, `None`, `True` и мусор (dict/list) сводятся к организации 1:
    # правило с тем же uid в группе без orgId — коллизия, а не «другая org».
    found = gal007(
        group([rule(uid="dup", title="A")], org_id=org_id),
        group([rule(uid="dup", title="B")]),
    )
    assert pairs(found) == [("GAL007", "error")]


def test_fractional_org_id_is_its_own_org():
    # 1.5 не целое: `str(1.5) == "1.5"`, с организацией 1 не сливается…
    assert (
        gal007(
            group([rule(uid="dup", title="A")], org_id=1.5),
            group([rule(uid="dup", title="B")], org_id=1),
        )
        == []
    )
    # …но два 1.5 — одна и та же организация.
    assert pairs(
        gal007(
            group([rule(uid="dup", title="A")], org_id=1.5),
            group([rule(uid="dup", title="B")], org_id=1.5),
        )
    ) == [("GAL007", "error")]


def test_folder_does_not_matter_for_uid_uniqueness():
    # uid живёт в организации: одна и та же uid в разных папках — коллизия.
    found = gal007(
        group([rule(uid="dup", title="A")], folder="Ops"),
        group([rule(uid="dup", title="B")], folder="Dev"),
    )
    assert pairs(found) == [("GAL007", "error")]
    assert "folder" not in found[0].message


# --- folder: представление одной и той же папки ---------------------------


@pytest.mark.parametrize("folder", ["", None, ABSENT])
def test_empty_and_missing_folder_are_the_same_folder_for_title(folder):
    # Отсутствие folder, `folder: ""` и `folder: null` — «корень», одна папка.
    found = gal007(
        group([rule(uid="a", title="Disk full")], folder=folder),
        group([rule(uid="b", title="Disk full")], name="g2"),
    )
    assert pairs(found) == [("GAL007", "warning")]
    assert "folder=—" in found[0].message


def test_numeric_folder_matches_its_string_form():
    # `folder: 5` и `folder: "5"` — одна папка после нормализации в строку.
    found = gal007(
        group([rule(uid="a", title="Disk full")], folder=5),
        group([rule(uid="b", title="Disk full")], name="g2", folder="5"),
    )
    assert pairs(found) == [("GAL007", "warning")]
    assert "folder=5" in found[0].message


def test_non_string_folder_degrades_to_root_folder():
    # Словарь в folder Grafana не примет; линтер молча считает его «корнем»,
    # поэтому title сталкивается с правилом без folder вообще.
    found = gal007(
        group([rule(uid="a", title="Disk full")], folder={"name": "Ops"}),
        group([rule(uid="b", title="Disk full")], name="g2"),
    )
    assert pairs(found) == [("GAL007", "warning")]
    assert "folder=—" in found[0].message


def test_same_title_in_different_folders_of_one_org_is_clean():
    assert (
        gal007(
            group([rule(uid="a", title="Disk full")], org_id=1, folder="Ops"),
            group([rule(uid="b", title="Disk full")], org_id=1, folder="Dev"),
        )
        == []
    )


def test_folder_uid_only_groups_collide_although_folders_differ():
    # Дефект-наблюдение: `folderUid` линтер не читает, поэтому правила из
    # разных папок (по folderUid) дают предупреждение о дубле title.
    found = gal007(
        group([rule(uid="a", title="Disk full")], org_id=0, folderUid="ops"),
        group([rule(uid="b", title="Disk full")], name="g2", org_id=0, folderUid="dev"),
    )
    assert pairs(found) == [("GAL007", "warning")]


# --- дубли внутри документа ---------------------------------------------


def test_duplicate_uid_and_title_inside_one_group_have_different_levels():
    found = findings_for(
        group(
            [rule(uid="dup", title="Same"), rule(uid="dup", title="Same")],
            org_id=7,
            folder="Ops",
        )
    )
    assert pairs(found) == [("GAL007", "error"), ("GAL007", "warning")]
    error, warning = found
    assert "orgId=7" in error.message and "folder" not in error.message
    assert "orgId=7" in warning.message and "folder=Ops" in warning.message


def test_third_duplicate_reports_the_first_rule_as_owner():
    found = gal007(
        group([rule(uid="dup", title="A"), rule(uid="dup", title="B"), rule(uid="dup", title="C")])
    )
    assert len(found) == 2
    assert all("уже занят правилом 'A'" in f.message for f in found)


def test_duplicate_title_across_groups_of_one_folder_counts_each_time():
    found = gal007(
        group([rule(uid="a", title="T")], name="g1", folder="F"),
        group([rule(uid="b", title="T")], name="g2", folder="F"),
        group([rule(uid="c", title="T")], name="g3", folder="F"),
    )
    assert pairs(found) == [("GAL007", "warning"), ("GAL007", "warning")]
    assert [f.group for f in found] == ["g2", "g3"]


# --- uid и title — независимые поля --------------------------------------


def test_uid_and_title_are_independent_fields_and_case_sensitive():
    # uid одного правила не сталкивается с title другого…
    assert gal007(group([rule(uid="X", title="A"), rule(uid="B", title="X")])) == []
    # …и оба поля сравниваются без нормализации регистра.
    assert gal007(group([rule(uid="A", title="Disk"), rule(uid="a", title="disk")])) == []


def test_empty_uid_and_empty_title_are_not_registered():
    # Пустая uid не занимает имя в организации (title у обоих есть → нет и GAL012).
    assert findings_for(group([rule(uid="", title="A"), rule(uid="", title="B")])) == []
    # Пустой title не занимает имя в папке (uid у обоих есть).
    assert findings_for(group([rule(uid="a", title=""), rule(uid="b", title="")])) == []


def test_rule_without_uid_still_occupies_its_title():
    bare = rule(uid=None, title="Only title")
    found = gal007(group([bare, rule(uid="b", title="Only title")]))
    assert pairs(found) == [("GAL007", "warning")]
    assert found[0].rule == "Only title"


def test_recording_rule_uid_collides_with_alert_rule_uid():
    recording = {"uid": "shared", "title": "Rec", "record": {"from": "A", "metric": "m"}}
    found = gal007(group([rule(uid="shared", title="Alert"), recording]))
    assert pairs(found) == [("GAL007", "error")]
    assert "уже занят правилом 'Alert'" in found[0].message


# --- несколько документов / файлов --------------------------------------


def test_two_documents_in_one_file_share_uid_state(tmp_path):
    path = tmp_path / "multi.yml"
    path.write_text(
        dump(group([rule(uid="shared", title="A")]))
        + "---\n"
        + dump(group([rule(uid="shared", title="B")], name="g2")),
        encoding="utf-8",
    )
    found = [f for f in lint_path(path) if f.code == "GAL007"]
    assert pairs(found) == [("GAL007", "error")]
    assert str(path) == found[0].path


def test_two_documents_in_one_file_collide_on_title_only_within_same_folder(tmp_path):
    path = tmp_path / "multi.yml"
    first = doc(group([rule(uid="a", title="Same")], folder="Ops"))
    second = doc(group([rule(uid="b", title="Same")], name="g2", folder="Ops"))
    other = doc(group([rule(uid="c", title="Same")], name="g3", folder="Dev"))
    path.write_text(
        "\n---\n".join(yaml.safe_dump(d, allow_unicode=True) for d in (first, second, other)),
        encoding="utf-8",
    )
    found = [f for f in lint_path(path) if f.code == "GAL007"]
    assert pairs(found) == [("GAL007", "warning")]
    assert "folder=Ops" in found[0].message


def test_lint_path_with_shared_state_catches_cross_file_duplicates_both_ways(tmp_path):
    one = dump(group([rule(uid="shared", title="Same")], folder="F"))
    first = tmp_path / "a.yml"
    second = tmp_path / "b.yml"
    first.write_text(one, encoding="utf-8")
    second.write_text(one, encoding="utf-8")

    forward = LintState()
    assert [f.code for f in lint_path(first, state=forward) if f.code == "GAL007"] == []
    assert pairs([f for f in lint_path(second, state=forward) if f.code == "GAL007"]) == [
        ("GAL007", "error"),
        ("GAL007", "warning"),
    ]

    # Порядок файлов решает, кто «первый»: обратный обход даёт тот же результат.
    backward = LintState()
    assert [f.code for f in lint_path(second, state=backward) if f.code == "GAL007"] == []
    assert pairs([f for f in lint_path(first, state=backward) if f.code == "GAL007"]) == [
        ("GAL007", "error"),
        ("GAL007", "warning"),
    ]


def test_cli_shares_state_across_files_for_uid(tmp_path, capsys):
    one = dump(group([rule(uid="shared", title="A")]))
    other = dump(group([rule(uid="shared", title="B")], name="g2"))
    first = tmp_path / "a.yml"
    second = tmp_path / "b.yml"
    first.write_text(one, encoding="utf-8")
    second.write_text(other, encoding="utf-8")

    assert main([str(first), str(second), "--format", "json"]) == EXIT_FINDINGS
    payload = json.loads(capsys.readouterr().out)
    assert payload["errors"] == 1
    assert payload["findings"][0]["code"] == "GAL007"
    assert "orgId=1" in payload["findings"][0]["message"]


def test_cli_duplicate_title_is_warning_and_needs_strict_to_fail(tmp_path, capsys):
    one = dump(group([rule(uid="a", title="Same")], folder="Ops"))
    other = dump(group([rule(uid="b", title="Same")], name="g2", folder="Ops"))
    first = tmp_path / "a.yml"
    second = tmp_path / "b.yml"
    first.write_text(one, encoding="utf-8")
    second.write_text(other, encoding="utf-8")

    assert main([str(first), str(second), "--format", "json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["warnings"] == 1 and payload["errors"] == 0
    finding = payload["findings"][0]
    assert (finding["code"], finding["level"]) == ("GAL007", "warning")
    assert "orgId=1" in finding["message"] and "folder=Ops" in finding["message"]

    assert main([str(first), str(second), "--strict"]) == EXIT_FINDINGS


def test_cli_reports_duplicates_across_orgs_as_clean(tmp_path, capsys):
    one = yaml.safe_dump(
        doc(group([rule(uid="shared", title="Same")], org_id=1, folder="F")), allow_unicode=True
    )
    other = yaml.safe_dump(
        doc(group([rule(uid="shared", title="Same")], name="g2", org_id=2, folder="F")),
        allow_unicode=True,
    )
    first = tmp_path / "a.yml"
    second = tmp_path / "b.yml"
    first.write_text(one, encoding="utf-8")
    second.write_text(other, encoding="utf-8")
    assert main([str(first), str(second), "--format", "json"]) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["findings"] == []


# --- контракт накопительного состояния ----------------------------------


def test_same_state_accumulates_and_reports_duplicates_on_repeat():
    state = LintState()
    document = doc(group([rule(uid="x", title="T")]))

    assert [f.code for f in lint_document(document, state=state)] == []
    assert pairs([f for f in lint_document(document, state=state) if f.code == "GAL007"]) == [
        ("GAL007", "error"),
        ("GAL007", "warning"),
    ]


def test_state_does_not_leak_between_independent_runs(tmp_path):
    # Контракт «состояние копится» требует нового LintState на прогон: без него
    # повторные вызовы и повторные файлы дают ложные GAL007.
    document = doc(group([rule(uid="x", title="T")]))
    for _ in range(3):
        assert lint_document(document, state=LintState()) == []

    one = yaml.safe_dump(document, allow_unicode=True)
    first = tmp_path / "a.yml"
    second = tmp_path / "b.yml"
    first.write_text(one, encoding="utf-8")
    second.write_text(one, encoding="utf-8")
    # По умолчанию у lint_path своё состояние на файл — кросс-файловых дублей нет.
    assert lint_path(first) == [] and lint_path(second) == []
