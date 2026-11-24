"""GAL005: `<` в тексте аннотаций.

Символ `<` заставляет Grafana слать сообщение с parse_mode=HTML; Telegram
отвечает 400 и алерт теряется молча. Здесь проверяется точное *число*
находок GAL005, поведение на безопасных символах (`>` и `&`), на нестроковых
значениях аннотаций и на вырожденных формах блока `annotations`.

Тесты самодостаточны: базовое правило строится локально (не импортируется из
tests/), чтобы не зависеть от чужих фикстур.
"""

from __future__ import annotations

import pytest
import yaml

from grafana_alert_lint.linter import Finding, lint_document

# --- helpers ---------------------------------------------------------------


def build_rule(**overrides):
    """Валидное во всех прочих отношениях правило: единственный возможный
    источник находок — блок `annotations`."""
    rule = {
        "uid": "r1",
        "title": "Правило",
        "condition": "B",
        "for": "5m",
        "noDataState": "OK",
        "execErrState": "Error",
        "labels": {"severity": "warning"},
        "annotations": {"summary": "Свободно меньше 10 процентов"},
        "data": [
            {
                "refId": "A",
                "model": {
                    "datasource": {"type": "prometheus", "uid": "prometheus"},
                    "expr": "up",
                    "refId": "A",
                },
            },
            {
                "refId": "B",
                "model": {
                    "datasource": {"type": "__expr__", "uid": "__expr__"},
                    "expression": "A",
                    "refId": "B",
                },
            },
        ],
    }
    rule.update(overrides)
    return {"groups": [{"name": "g", "interval": "1m", "rules": [rule]}]}


def findings(doc) -> list[Finding]:
    return lint_document(doc)


def gal005(doc) -> list[Finding]:
    return [f for f in findings(doc) if f.code == "GAL005"]


def gal005_keys(doc) -> list[str]:
    """Ключи аннотаций из сообщений GAL005 (сообщение — `'<' в annotations.<key>: ...`)."""
    keys = []
    for finding in gal005(doc):
        prefix = "'<' в annotations."
        assert finding.message.startswith(prefix), finding.message
        keys.append(finding.message[len(prefix) :].split(":", 1)[0])
    return keys


# --- базовая линия ---------------------------------------------------------


def test_base_rule_is_clean_without_angle_brackets():
    assert findings(build_rule()) == []


# --- один `<` в разных ключах ---------------------------------------------


@pytest.mark.parametrize("key", ["summary", "description", "runbook_url"])
def test_angle_bracket_in_standard_annotation(key):
    doc = build_rule(annotations={"summary": "ок", key: "диск <10%"})
    found = gal005(doc)
    assert len(found) == 1
    assert found[0].level == "error"
    assert gal005_keys(doc) == [key]


def test_angle_bracket_in_custom_annotation_key():
    doc = build_rule(annotations={"summary": "ок", "my_note": "порог < 5"})
    assert gal005_keys(doc) == ["my_note"]


def test_angle_bracket_in_only_annotation_without_summary():
    # summary отсутствует: GAL009 — вкусовая проверка и по умолчанию молчит,
    # поэтому единственная находка — GAL005.
    doc = build_rule(annotations={"description": "если < 5 минут"})
    assert [f.code for f in findings(doc)] == ["GAL005"]


# --- безвредные символы ----------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "cpu > 90%",
        "если > 5 минут и > 2 реплик",
        "A & B",
        "A &amp; B",
        "Tom & Jerry &amp; Co",
        "x >= 5, y != 3",
    ],
)
def test_safe_characters_do_not_trigger_gal005(text):
    assert gal005(build_rule(annotations={"summary": text})) == []


# --- формы с `<` -----------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "<>",
        "<3",
        "< b",
        "<b>жирный</b>",
        "<br/>",
        "</b>",
        "a<b",
        "<b",
    ],
)
def test_every_angle_bracket_form_is_flagged(text):
    assert len(gal005(build_rule(annotations={"summary": text}))) == 1


def test_two_angle_brackets_in_one_value_still_one_finding():
    # Находка — на аннотацию, а не на символ.
    doc = build_rule(annotations={"summary": "<b>a</b> и < 5"})
    assert len(gal005(doc)) == 1


# --- многострочный YAML-блок ----------------------------------------------


MULTILINE = """
groups:
  - name: g
    interval: 1m
    rules:
      - uid: r1
        title: Правило
        condition: B
        for: 5m
        noDataState: OK
        execErrState: Error
        labels:
          severity: warning
        annotations:
          summary: "ок"
          description: |
            Первая строка без проблем.
            Вторая строка: порог < 5 процентов.
            Третья строка тоже без проблем.
        data:
          - refId: A
            model:
              datasource: {type: prometheus, uid: prometheus}
              expr: up
              refId: A
          - refId: B
            model:
              datasource: {type: __expr__, uid: __expr__}
              expression: A
              refId: B
"""


def test_multiline_block_scalar_with_angle_bracket():
    doc = yaml.safe_load(MULTILINE)
    found = gal005(doc)
    assert len(found) == 1
    assert gal005_keys(doc) == ["description"]
    # Символ внутри блока сохранился после разбора YAML.
    assert "< 5" in doc["groups"][0]["rules"][0]["annotations"]["description"]


# --- юникод ---------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "🔥 диск <10% — срочно",
        "порог < 5 % 中文 émoji 🚨",
        "<10% (≤)",
    ],
)
def test_angle_bracket_next_to_unicode(text):
    assert len(gal005(build_rule(annotations={"summary": text}))) == 1


# --- нестроковые значения аннотаций --------------------------------------


@pytest.mark.parametrize(
    "value",
    [5, 1.5, True, False, None, ["<b>", "< 5"], {"inner": "< 5"}],
)
def test_non_string_annotation_value_is_ignored(value):
    # Не строка → проверка не применяется, падения нет.
    assert gal005(build_rule(annotations={"summary": "ок", "weird": value})) == []


def test_numeric_summary_is_ignored_but_does_not_crash():
    doc = build_rule(annotations={"summary": 42, "description": "ok"})
    assert gal005(doc) == []


# --- вырожденные формы блока annotations ---------------------------------


def test_annotations_absent():
    rule = build_rule()
    del rule["groups"][0]["rules"][0]["annotations"]
    assert gal005(rule) == []


@pytest.mark.parametrize("annotations", [{}, [], "строка", 7, None])
def test_annotations_not_a_mapping(annotations):
    rule = build_rule()
    rule["groups"][0]["rules"][0]["annotations"] = annotations
    assert gal005(rule) == []


def test_annotations_loaded_from_yaml_as_list():
    text = """
groups:
  - name: g
    interval: 1m
    rules:
      - uid: r1
        title: Правило
        condition: B
        for: 5m
        noDataState: OK
        execErrState: Error
        annotations:
          - "< 5"
        data:
          - refId: A
            model:
              datasource: {type: prometheus, uid: prometheus}
              expr: up
              refId: A
          - refId: B
            model:
              datasource: {type: __expr__, uid: __expr__}
              expression: A
              refId: B
"""
    assert gal005(yaml.safe_load(text)) == []


# --- число находок при нескольких аннотациях ------------------------------


def test_two_broken_annotations_give_two_findings():
    doc = build_rule(
        annotations={
            "summary": "диск <10%",
            "description": "если < 5 минут",
            "runbook_url": "https://wiki/ok",
        }
    )
    found = gal005(doc)
    assert len(found) == 2
    assert sorted(gal005_keys(doc)) == ["description", "summary"]
    assert all(f.level == "error" for f in found)


def test_all_four_broken_annotations_give_four_findings():
    doc = build_rule(
        annotations={
            "summary": "< 5%",
            "description": "<b>сбой</b>",
            "runbook_url": "https://wiki/x<y",
            "custom": "<3",
        }
    )
    assert len(gal005(doc)) == 4


# --- ключ-не-строка ------------------------------------------------------>


def test_non_string_key_is_stringified_in_message():
    doc = build_rule(annotations={123: "порог < 5", "summary": "ок"})
    assert gal005_keys(doc) == ["123"]


# --- labels: проверки нет ------------------------------------------------


def test_angle_bracket_in_labels_is_not_gal005():
    # Факт: GAL005 смотрит только `annotations`; `<` в labels линтер не
    # проверяет (лейблы уезжают в уведомления иначе, чем аннотации).
    doc = build_rule(labels={"severity": "warning", "note": "< 5"})
    assert gal005(doc) == []
    assert findings(doc) == []


# --- шаблоны Go ----------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "{{ if lt $values.B 5 }}низко{{ end }} <",
        '{{ index $labels "a<b" }}',
    ],
)
def test_go_template_with_angle_bracket_is_flagged(text):
    assert len(gal005(build_rule(annotations={"summary": text}))) == 1


@pytest.mark.parametrize(
    "text",
    [
        "{{ $labels.instance }}",
        "{{ if gt $values.B 5 }}высоко{{ end }}",
        '{{ printf "%.2f" $values.B }}',
    ],
)
def test_go_template_without_angle_bracket_is_safe(text):
    assert gal005(build_rule(annotations={"summary": text})) == []
