# galint — линтер правил алертов Grafana

Правила алертов — это код, но проверяют их глазами и «а пришло ли сообщение».
`galint` читает провижиненные правила Grafana и находит то, что не ломает
деплой и не видно в UI: правила, которые **выглядят рабочими и не работают**.

```console
$ galint metrics/grafana/provisioning/alerting/
alerts.yml:niki-server/Node exporter недоступен: error GAL001 noDataState=Alerting при
фильтрующем выражении 'up{job="node"} == 0': на здоровом сервисе серия пуста,
правило застрянет в Firing и никогда не закроется

ошибок: 1, предупреждений: 0
```

## Откуда взялось

Две ошибки на живом сервере, каждая — сутки-двое мусора в канале дежурства.
Полные разборы: [0003](https://github.com/RealNikiHere/niki-prod/blob/main/docs/postmortems/0003-2026-11-24-alert-stuck-firing.md)
и [0004](https://github.com/RealNikiHere/niki-prod/blob/main/docs/postmortems/0004-2026-11-24-planned-outage-alert-storm.md).

**1. `up{job="node"} == 0` и `noDataState: Alerting`.** Когда сервер здоров,
это выражение возвращает не ноль, а **ничего**: серия `up=1` отфильтрована.
Grafana видит пустой результат, `noDataState: Alerting` превращает пустоту в
аварию. Правило горит всегда и не может закрыться — `Resolved` не придёт
никогда. Проверка «остановить exporter» при этом проходит: остановили —
`Firing`, подняли — `Resolved`. Мониторинг работал строго наоборот.

**2. `<` в тексте аннотации.** Grafana отправляет уведомления в Telegram с
`parse_mode=HTML`. Символ `<` начинает тег, Telegram отвечает `400`, алерт
срабатывает и **теряется**: ошибка видна только в логах Grafana. Правило
было исправно, а сообщения не было.

Обе ошибки ловятся статически, без живого Grafana.

## Установка

```bash
pipx install grafana-alert-lint     # из PyPI (после публикации)
# или
pip install git+https://github.com/RealNikiHere/grafana-alert-lint
```

## Использование

```bash
galint path/to/alert-rules.yml            # один файл
galint metrics/grafana/provisioning/      # каталог, рекурсивно
galint rules/ --format json               # для CI и парсинга
galint rules/ --strict                    # предупреждения = ошибки
```

Коды возврата: `0` — чисто, `1` — есть находки, `2` — файл не читается или
не разбирается как YAML (в CI это отдельный сигнал: правила сломаны
синтаксически, а не по смыслу).

В GitHub Actions:

```yaml
- run: pipx install grafana-alert-lint && galint deploy/grafana/alerting/
```

## Что проверяется

| Код | Уровень | Проверка |
|-----|---------|----------|
| GAL001 | error | `noDataState: Alerting` при фильтрующем PromQL (`== N`, `!= N`): пустая серия на здоровом сервисе = вечный `Firing` |
| GAL002 | warning | `noDataState: NoData`: плановый разрыв метрик (сон, обслуживание) выглядит как авария |
| GAL003 | error | `noDataState` не задан или неизвестен |
| GAL004 | warning | нет `for` — срабатывание на первом промахе |
| GAL005 | error | `<` или `>` в аннотации: Telegram `400`, сообщение теряется |
| GAL006 | error | `condition` ссылается на несуществующий `refId` / не задан |
| GAL007 | error | повторяющийся `uid` или `title` — провижининг перезапишет правило |
| GAL008 | warning | нет `labels.severity` — нечем маршрутизировать |
| GAL009 | warning | нет `annotations.summary` — сообщение без сути |
| GAL010 | warning | нет `execErrState` — ошибка вычисления обрабатывается по умолчанию |
| GAL011 | warning | `for` короче интервала группы — дебаунс меньше шага оценки |
| GAL012 | error | у правила нет ни `uid`, ни `title` — его нельзя найти или замьютить |

Проверки читают структуру провижининга (`groups[].rules[]`), тот же формат,
что отдаёт Grafana API и что лежит в `provisioning/alerting/`.

## Что он НЕ проверяет

Честно, потому что остальное — не статический анализ:

- существует ли метрика и правильные ли у неё лейблы (нужен живой Prometheus);
- правильна ли маршрутизация: contact point, mute timings, доставка;
- не сработает ли правило на здоровом сервисе из-за неверного порога —
  это проверяется экспериментом, а не линтером;
- панели дашбордов, recording rules, права доступа.

Для PromQL есть `promtool check rules`, для дашбордов — `grizzly`. `galint`
дополняет их, а не заменяет: он про семантику алертинга, а не про синтаксис.

## Разработка

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest && ruff check .
```

Фикстура `tests/fixtures/regression-0003.yml` — настоящее правило из инцидента;
тест требует, чтобы линтер на нём падал. CI дополнительно проверяет, что
`galint` возвращает `1` на этой фикстуре и `0` на чистой.

## Лицензия

MIT.
