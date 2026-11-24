"""Границы полей правила: GAL003 (noDataState), GAL004 (for), GAL006
(condition/refId/data), GAL010 (execErrState), GAL012 (идентичность правила)
и GAL013 (interval группы).

Каждая проверка фиксирует наблюдаемый контракт линтера: код, уровень находки и
— где важно — текст сообщения. Существующие tests/ покрывают «счастливые»
значения и общую устойчивость к кривому входу; здесь именно края: регистр,
bool/число/список/словарь на месте строки, пустая строка, отрицательные и
дробные длительности.

Тесты, чей docstring начинается с «ФАКТ (спорно)», фиксируют текущее поведение,
которое выглядит дефектом: они не должны «покраснеть» от исправления молча —
сначала решается вопрос из отчёта.
"""

from __future__ import annotations

import pytest

from grafana_alert_lint.linter import lint_document


def rule(**overrides):
    """Валидное правило: любая находка в тесте — следствие overrides."""
    base = {
        "uid": "r1",
        "title": "Правило",
        "condition": "B",
        "for": "5m",
        "noDataState": "OK",
        "execErrState": "Error",
        "labels": {"severity": "warning"},
        "annotations": {"summary": "Свободно меньше 10 процентов"},
        "data": [
            {"refId": "A", "model": {"expr": "up", "refId": "A"}},
            {"refId": "B", "model": {"type": "threshold", "expression": "A", "refId": "B"}},
        ],
    }
    base.update(overrides)
    return base


def run(one_rule, *, interval="1m", opinionated=True):
    """Находки одного правила в группе с заданным интервалом."""
    doc = {"groups": [{"name": "g", "interval": interval, "rules": [one_rule]}]}
    return lint_document(doc, opinionated=opinionated)


def codes(one_rule, **kwargs):
    return [(finding.code, finding.level) for finding in run(one_rule, **kwargs)]


# --- GAL003: допустимые и недопустимые noDataState -----------------------


def test_no_data_state_valid_values_never_report_gal003():
    # Все четыре значения Grafana принимает. NoData валиден, но осуждается
    # вкусовой GAL002 — и только при --opinionated.
    for value in ("OK", "Alerting", "KeepLast"):
        assert codes(rule(noDataState=value)) == [], value
        assert codes(rule(noDataState=value), opinionated=False) == [], value
    assert codes(rule(noDataState="NoData")) == [("GAL002", "warning")]
    assert codes(rule(noDataState="NoData"), opinionated=False) == []


@pytest.mark.parametrize(
    ("value", "fragment"),
    [
        # строки не из набора: сравнение регистрозависимое
        ("Error", "допустимо"),  # значение execErrState, для noDataState невалидно
        ("ok", "допустимо"),
        ("alerting", "допустимо"),
        ("keepLast", "допустимо"),
        ("okk", "допустимо"),
        ("true", "допустимо"),
        ("", "допустимо"),
        ("  ", "допустимо"),
        # скаляры as_scalar_str приводит к строке: "1"/"True" не из набора
        (1, "допустимо"),
        (True, "допустимо"),
        (3.5, "допустимо"),
        # список/словарь — отдельная ветка сообщения
        ([], "не строка и не число"),
        (["OK"], "не строка и не число"),
        ({"state": "OK"}, "не строка и не число"),
    ],
)
def test_invalid_no_data_state_is_gal003_error(value, fragment):
    findings = run(rule(noDataState=value))
    assert [(f.code, f.level) for f in findings] == [("GAL003", "error")]
    assert fragment in findings[0].message


def test_no_data_state_none_is_reported_as_missing():
    # `noDataState:` без значения неотличим от отсутствия ключа — и это верно.
    explicit = run(rule(noDataState=None))
    missing = run({k: v for k, v in rule().items() if k != "noDataState"})
    assert [(f.code, f.level) for f in explicit] == [("GAL003", "error")]
    assert explicit[0].message == missing[0].message
    assert "не задан" in explicit[0].message


# --- GAL004: `for` как длительность Grafana ------------------------------


@pytest.mark.parametrize(
    ("value", "fragment"),
    [
        ("", "нет for"),
        ("30", "не длительность и не число секунд"),  # строка без единицы
        ("30 s", "не длительность и не число секунд"),  # пробел внутри
        ("1h 30m", "не длительность и не число секунд"),
        ("5m5", "не длительность и не число секунд"),
        ("1.5s", "не длительность и не число секунд"),  # только целые части
        (True, "не длительность и не число секунд"),  # bool — не секунды
        (False, "не длительность и не число секунд"),
        ([], "не длительность и не число секунд"),
        ({}, "не длительность и не число секунд"),
    ],
)
def test_invalid_for_is_gal004_warning(value, fragment):
    findings = run(rule(**{"for": value}))
    assert [(f.code, f.level) for f in findings] == [("GAL004", "warning")]
    assert fragment in findings[0].message


def test_numeric_for_is_seconds_and_compared_with_interval():
    # Число 30 — это 30 секунд: не GAL004, но короче интервала группы 60s.
    assert codes(rule(**{"for": 30})) == [("GAL011", "warning")]


@pytest.mark.parametrize("value", ["30s", "1h30m", "1w", "2y", "500ms", "5m"])
def test_valid_for_durations_are_not_gal004(value):
    assert "GAL004" not in [code for code, _ in codes(rule(**{"for": value}))], value


def test_zero_for_is_valid_and_negative_for_is_reported():
    """`for: 0` — нулевой дебаунс; отрицательную длительность Grafana не примет."""
    assert codes(rule(**{"for": 0})) == []
    assert ("GAL004", "warning") in codes(rule(**{"for": -30}))


# --- GAL006: condition / refId / data ------------------------------------


def test_condition_resolves_numeric_ref_id():
    numeric = [
        {"refId": 1, "model": {"expr": "up", "refId": 1}},
        {"refId": 2, "model": {"type": "threshold", "expression": "1", "refId": 2}},
    ]
    assert codes(rule(condition=1, data=numeric)) == []
    # as_scalar_str приводит обе стороны к строке, поэтому 1 == "1".
    stringified = [
        {"refId": "1", "model": {"expr": "up", "refId": "1"}},
        {"refId": "2", "model": {"type": "threshold", "expression": "1", "refId": "2"}},
    ]
    assert codes(rule(condition=1, data=stringified)) == []


def test_empty_condition_reports_missing_ref_id():
    """ФАКТ (спорно): `condition: ""` попадает в ветку «нет такого refId».

    Ошибка правильная, но сообщение «ссылается на отсутствующий refId» для
    пустой строки вводит в заблуждение: правило не ссылается ни на что.
    """
    findings = run(rule(condition=""))
    assert [(f.code, f.level) for f in findings] == [("GAL006", "error")]
    assert "ссылается на отсутствующий refId" in findings[0].message


@pytest.mark.parametrize(
    ("value", "fragment"),
    [
        (["A"], "не строка"),
        ({"ref": "A"}, "не строка"),
        (1.5, "ссылается на отсутствующий refId"),  # скаляр → "1.5", такого refId нет
    ],
)
def test_non_string_condition_is_gal006_error(value, fragment):
    findings = run(rule(condition=value))
    assert [(f.code, f.level) for f in findings] == [("GAL006", "error")]
    assert fragment in findings[0].message


def test_data_without_any_ref_id_is_error():
    findings = run(rule(data=[{"model": {"expr": "up"}}, {"refId": None}]))
    assert [(f.code, f.level) for f in findings] == [("GAL006", "error")]
    assert "нет ни одного refId" in findings[0].message


def test_duplicate_ref_ids_are_not_reported():
    """ФАКТ (спорно): одинаковые refId внутри одного правила не ловятся.

    Grafana отвергает `data` с повторяющимся refId, но проверки нет: множество
    refId схлопывает дубли, condition="A" выглядит корректным — GAL006 молчит.
    """
    data = [
        {"refId": "A", "model": {"expr": "up", "refId": "A"}},
        {"refId": "A", "model": {"expr": "up == 0", "refId": "A"}},
    ]
    assert codes(rule(condition="A", data=data)) == []


# --- GAL010: execErrState ----------------------------------------------


@pytest.mark.parametrize("value", ["OK", "Alerting", "Error", "KeepLast"])
def test_exec_err_state_accepts_all_grafana_values(value):
    assert "GAL010" not in [code for code, _ in codes(rule(execErrState=value))], value
    assert codes(rule(execErrState=value), opinionated=False) == []


@pytest.mark.parametrize(
    ("value", "fragment"),
    [
        ("error", "допустимо"),  # регистр важен
        ("ok", "допустимо"),
        ("keeplast", "допустимо"),
        ("okk", "допустимо"),
        ("", "допустимо"),
        ("  ", "допустимо"),
        (True, "допустимо"),
        (1, "допустимо"),  # "1" не из набора
        ([], "не строка"),
        ({"state": "Error"}, "не строка"),
    ],
)
def test_invalid_exec_err_state_is_gal010_warning(value, fragment):
    findings = run(rule(execErrState=value))
    assert [(f.code, f.level) for f in findings] == [("GAL010", "warning")]
    assert fragment in findings[0].message


def test_exec_err_state_missing_and_none_are_equal():
    explicit = run(rule(execErrState=None))
    missing = run({k: v for k, v in rule().items() if k != "execErrState"})
    assert [(f.code, f.level) for f in explicit] == [("GAL010", "warning")]
    assert explicit[0].message == missing[0].message
    assert "нет execErrState" in explicit[0].message


# --- GAL012: идентичность правила (uid / title) --------------------------


@pytest.mark.parametrize(
    ("uid", "title"),
    [
        (0, None),
        (None, 0),
        (False, None),
        (None, False),
        (0, 0),
        (False, False),
        (" ", None),
        (None, " "),
        ("  ", "  "),
    ],
)
def test_falsy_and_whitespace_identity_counts_as_present(uid, title):
    """ФАКТ (спорно): `uid: 0`, `uid: false` и `uid: " "` считаются идентичностью.

    as_scalar_str даёт "0"/"False"/" ", поле выглядит заданным, и GAL012 молчит.
    Grafana такой uid (не строка либо пробелы) не примет, а правило остаётся
    «ненайденным»: ни найти, ни замьютить.
    """
    assert "GAL012" not in [code for code, _ in codes(rule(uid=uid, title=title))]


@pytest.mark.parametrize(
    ("uid", "title"),
    [("üñî-код-💥", None), (None, "Правило с юникодом 💥"), ("日本語", "日本語")],
)
def test_unicode_identity_is_clean(uid, title):
    # Юникод в uid/title — норма для провижининга: находок быть не должно,
    # и подпись правила не должна падать на нём.
    assert run(rule(uid=uid, title=title)) == []


@pytest.mark.parametrize(("uid", "title"), [("", ""), ("", None), (None, "")])
def test_empty_string_identity_is_error(uid, title):
    findings = run(rule(uid=uid, title=title))
    assert [(f.code, f.level) for f in findings] == [("GAL012", "error")]
    assert "нет ни uid, ни title" in findings[0].message
    # Без идентичности правило подписывается по индексу.
    assert findings[0].rule.startswith("rule[")


# --- GAL013: interval группы --------------------------------------------


@pytest.mark.parametrize("value", ["jedes Mal", "1.5s", "30", "1h 30m", ["1m"], {"v": "1m"}, True])
def test_invalid_group_interval_is_gal013_error(value):
    findings = run(rule(), interval=value)
    gal013 = [f for f in findings if f.code == "GAL013"]
    assert len(gal013) == 1
    assert gal013[0].level == "error"
    assert gal013[0].rule == "(группа)"
    assert "не разбирается как длительность Grafana" in gal013[0].message
    assert "например 30s, 1m, 1h30m" in gal013[0].message


def test_empty_group_interval_is_treated_as_absent():
    # `interval: ""` — пустое значение, а не мусор: Grafana подставит свой дефолт.
    assert [f.code for f in run(rule(**{"for": "30s"}), interval="")] == ["GAL011"]


def test_huge_group_interval_is_error_not_infinity():
    # int*float на 400-значном числе даёт OverflowError — это не длительность,
    # и находки правила при этом не теряются.
    findings = run(rule(), interval="9" * 400)
    assert [f.code for f in findings] == ["GAL013"]
    # GAL011 молчит: битый интервал не заменяется выдуманными 60 секундами.
    assert [f.code for f in run(rule(**{"for": "30s"}), interval="9" * 400)] == ["GAL013"]


def test_valid_or_absent_group_interval_is_silent():
    for value in ("30s", "1m", "1h30m", 60, 0.5, 3600):
        assert "GAL013" not in [f.code for f in run(rule(), interval=value)], value
    absent = {"groups": [{"name": "g", "rules": [rule(**{"for": "2m"})]}]}
    assert [f.code for f in lint_document(absent, opinionated=True)] == []


def test_zero_and_negative_group_interval_are_gal013():
    """Grafana требует interval больше нуля, поэтому 0 и −60 — ошибка GAL013.

    GAL011 при этом молчит: без валидного интервала сравнивать не с чем.
    """
    for interval in (0, -60, "0s", "-1m"):
        found = run(rule(**{"for": "30s"}), interval=interval)
        assert [f.code for f in found] == ["GAL013"], interval
        assert found[0].level == "error"
