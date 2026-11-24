"""GAL001 и разбор PromQL: где сравнение фильтрует серии, а где нет.

GAL001 срабатывает, только когда `noDataState: Alerting` и хотя бы одно
PromQL-выражение правила содержит сравнение *без* модификатора `bool`
(`is_filtering_expression` → True). Эти тесты фиксируют именно наблюдаемое
поведение: код находки `GAL001` и её уровень `error` — либо их отсутствие.

Все тесты используют «чистое» правило (см. `_rule`): единственная возможная
находка — GAL001, поэтому список находок однозначен. Каждый тест проверяет
разбор PromQL, а не прочие проверки.
"""

from __future__ import annotations

import pytest
import yaml

from grafana_alert_lint.linter import (
    is_filtering_expression,
    lint_document,
    query_expressions,
)

# Находка, которую ждём для фильтрующего выражения при noDataState=Alerting.
GAL001 = ("GAL001", "error")


def _rule(data):
    """Правило, в котором при корректном провижининге нет находок кроме GAL001."""
    rule = {
        "uid": "r1",
        "title": "Правило",
        "condition": "A",  # ссылается на существующий refId
        "for": "5m",
        "noDataState": "Alerting",
        "execErrState": "Error",
        "labels": {"severity": "critical"},
        "annotations": {"summary": "Свободно меньше 10 процентов"},
        "data": data,
    }
    return {"groups": [{"name": "g", "interval": "1m", "rules": [rule]}]}


def _one(expr):
    """Один PromQL-запрос с данным выражением (refId=A, condition ссылается на него)."""
    return [{"refId": "A", "model": {"expr": expr, "refId": "A"}}]


def _findings(data):
    """Пары (код, уровень) находок для правила с заданным `data`."""
    return [(f.code, f.level) for f in lint_document(_rule(data))]


def _gal001(expr):
    """Код и уровень по одному PromQL-выражению."""
    return _findings(_one(expr))


# --- модификатор bool во всех позициях -----------------------------------


def test_plain_comparison_filters_and_raises_gal001_error():
    # Опорный случай: `up == 0` при up=1 отбрасывает серию → GAL001 error.
    assert _gal001("up == 0") == [GAL001]
    assert is_filtering_expression("up == 0") is True


@pytest.mark.parametrize(
    "expr",
    [
        "up == bool 0",
        "up != bool 1",
        "up > bool 0",
        "up >= bool 1",
        "up < bool 0",
        "up <= bool 1",
        'up{job="node"} == bool 0',
        "rate(http_requests_total[5m]) != bool 0",
    ],
    ids=["eq", "neq", "gt", "gte", "lt", "lte", "eq-matcher", "neq-rate"],
)
def test_bool_modifier_never_filters(expr):
    # `bool` возвращает 0/1 для всех серий: пустого результата нет, GAL001 молчит.
    assert _gal001(expr) == []
    assert is_filtering_expression(expr) is False


# --- сравнения внутри матчеров: регексы, экранированные кавычки, строки --


@pytest.mark.parametrize(
    "expr",
    [
        r'up{job=~"a>b"}',
        r'up{msg="he said \"x > 1\""}',  # экранированные кавычки внутри "
        r"up{note='it\'s > 9'}",  # экранированная кавычка внутри '
        "up{note=`x > 1 and y < 2`}",  # backtick-строка с < и >
        r'up{job=~"a>b|c"} == bool 1',
        r'up{code=~"5..|4.."}',
    ],
    ids=["regex-gt", "escaped-dq", "escaped-sq", "backtick", "regex-plus-bool", "regex-codes"],
)
def test_comparison_inside_matcher_or_string_is_not_filtering(expr):
    # Содержимое матчеров и строковых литералов — не операторы сравнения.
    assert _gal001(expr) == []
    assert is_filtering_expression(expr) is False


def test_real_comparison_survives_noisy_matcher():
    # Матчер с `>` в регексе не должен прятать настоящее сравнение снаружи.
    assert _gal001(r'up{job=~"a>b"} > 0') == [GAL001]


# --- вложенные селекторы, агрегаты, offset, @, subquery ------------------


@pytest.mark.parametrize(
    "expr",
    [
        r'sum by (job) (rate(foo{code=~"5.."}[5m])) / sum(rate(foo[5m])) > 0.05',
        r"histogram_quantile(0.9, sum by (le) (rate(x[5m]))) > 0.5",
    ],
    ids=["sum-by-ratio", "histogram-quantile"],
)
def test_nested_selector_and_aggregate_comparison_is_filtering(expr):
    # Вложенные селекторы не мешают увидеть сравнение агрегата → GAL001.
    assert _gal001(expr) == [GAL001]


def test_aggregation_with_without_clause_and_bool_is_not_filtering():
    # `without`-агрегат с bool — сравнение есть, но не фильтрует.
    assert _gal001("sum(up) without (instance) > bool 0") == []


def test_subquery_comparison_is_filtering():
    # Subquery [5m:1m] не сбивает разбор: `> 0` снаружи фильтрует → GAL001.
    assert _gal001("max_over_time(up[5m:1m]) > 0") == [GAL001]


def test_offset_modifier_comparison_is_filtering():
    # offset не меняет смысл сравнения → GAL001.
    assert _gal001("up offset 1h > 0") == [GAL001]


def test_at_modifier_comparison_is_filtering():
    # `@`-модификатор не прячет сравнение → GAL001.
    assert _gal001("up @ 1700000000 < 1") == [GAL001]


# --- бинарные операторы and / or / unless --------------------------------


@pytest.mark.parametrize(
    "expr",
    [
        "foo > 1 or up",
        "up and on(job) foo > 0",
        "up unless on(job) foo > 0",
    ],
    ids=["or", "and", "unless"],
)
def test_comparison_in_either_operand_of_binary_operator_is_filtering(expr):
    # Сравнение в любой части бинарного выражения фильтрует → GAL001.
    assert _gal001(expr) == [GAL001]


def test_comparison_only_inside_unless_matcher_is_not_filtering():
    # `unless` без внешнего сравнения; `>` есть только в матчере → GAL001 молчит.
    assert _gal001('up unless foo{a="> 0"}') == []


def test_bool_alongside_plain_comparison_still_filters():
    # Один `bool` не спасает: второе сравнение без bool фильтрует → GAL001.
    assert _gal001("up > bool 0 and foo > 1") == [GAL001]


# --- label_replace: строка-замена vs внешнее сравнение --------------------


def test_comparison_inside_label_replace_string_is_not_filtering():
    # Замена `"== 0"` — строковый литерал, а не оператор → GAL001 молчит.
    assert _gal001('label_replace(up, "dst", "== 0", "src", "(.*)")') == []


def test_comparison_outside_label_replace_is_filtering():
    # label_replace с `$1` и настоящим `> 0` снаружи → GAL001.
    assert _gal001('label_replace(up, "dst", "$1", "src", "(.*)") > 0') == [GAL001]


# --- шаблонные $ и datasource __expr__ -----------------------------------


@pytest.mark.parametrize("expr", ["$var", "$var > 0"], ids=["bare", "bare-with-op"])
def test_expression_starting_with_template_variable_is_skipped(expr):
    # Выражение, начинающееся с `$`, считается шаблонным и не разбирается → GAL001 молчит.
    assert _gal001(expr) == []
    assert query_expressions({"data": _one(expr)}) == []


def test_interpolation_inside_real_query_is_still_parsed():
    # `$__rate_interval` в середине выражения не мешает: сравнение видно → GAL001.
    assert _gal001("rate(x[$__rate_interval]) > 0") == [GAL001]


def test_expr_datasource_uid_is_skipped():
    # Запрос с datasource.uid=__expr__ — вычисление Grafana, а не PromQL → GAL001 молчит.
    data = [
        {
            "refId": "A",
            "model": {"datasource": {"uid": "__expr__"}, "expression": "A > 0", "refId": "A"},
        }
    ]
    assert _findings(data) == []
    assert query_expressions({"data": data}) == []


# --- модели вычислений Grafana: type threshold/math/reduce/resample ------


@pytest.mark.parametrize("model_type", ["threshold", "math", "reduce", "resample"])
def test_calculation_model_types_are_not_promql(model_type):
    # У моделей вычислений `expression` — не PromQL; сравнение в ней не считается → GAL001 молчит.
    data = [{"refId": "A", "model": {"type": model_type, "expression": "A > 0", "refId": "A"}}]
    assert _findings(data) == []
    assert query_expressions({"data": data}) == []


# --- expr и expression одновременно, отсутствие expr, пустое, не строка, много


def test_both_expr_and_expression_are_parsed():
    # Запрос с both `expr` и `expression`: фильтрующий `expression` всё равно ловится → GAL001.
    data = [{"refId": "A", "model": {"expr": "up", "expression": "down > 1", "refId": "A"}}]
    assert _findings(data) == [GAL001]
    assert query_expressions({"data": data}) == ["up", "down > 1"]


def test_model_without_expr_has_no_promql():
    # Нет ни expr, ни expression → нечего разбирать, GAL001 молчит.
    data = [{"refId": "A", "model": {"refId": "A"}}]
    assert query_expressions({"data": data}) == []
    assert _findings(data) == []


@pytest.mark.parametrize(
    "expr",
    ["", 123, None, ["up == 0"]],
    ids=["empty-str", "int", "null", "list"],
)
def test_empty_or_non_string_expr_is_ignored(expr):
    # Пустое / нестроковое значение expr не превращается в выражение и не даёт GAL001.
    data = [{"refId": "A", "model": {"expr": expr, "refId": "A"}}]
    assert query_expressions({"data": data}) == []
    assert _findings(data) == []


def test_only_filtering_query_among_many_triggers_gal001():
    # Один фильтрующий запрос из нескольких даёт ровно одну находку GAL001.
    data = [
        {"refId": "A", "model": {"expr": "up", "refId": "A"}},
        {"refId": "C", "model": {"expr": "down > 1", "refId": "C"}},
        {"refId": "D", "model": {"expr": "up == bool 0", "refId": "D"}},
    ]
    assert _findings(data) == [GAL001]


def test_multiple_non_filtering_queries_are_clean():
    # Несколько запросов без фильтрующих сравнений → находок нет.
    data = [
        {"refId": "A", "model": {"expr": "up", "refId": "A"}},
        {"refId": "C", "model": {"expr": "down == bool 0", "refId": "C"}},
    ]
    assert _findings(data) == []


# --- известный разрыв: datasource строкой ---------------------------------


def test_expr_datasource_as_bare_string_is_skipped():
    # datasource строкой "__expr__" исключает запрос так же, как словарём.
    data = [
        {"refId": "A", "model": {"datasource": "__expr__", "expression": "A > 0", "refId": "A"}}
    ]
    assert _findings(data) == []


def test_baseline_rule_document_is_clean():
    # Страховка от тавтологии: сам шаблон без фильтрующего сравнения не даёт находок,
    # значит в тестах выше GAL001 появляется именно из-за сравнения в PromQL.
    assert _findings(_one("up")) == []
    assert lint_document(yaml.safe_load("groups: []")) == []
