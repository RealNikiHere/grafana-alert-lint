# galint — a linter for Grafana alerting rules

[English](README.md) | [Русский](README.ru.md)

[![CI](https://github.com/RealNikiHere/grafana-alert-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/RealNikiHere/grafana-alert-lint/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/grafana-alert-lint.svg)](https://pypi.org/project/grafana-alert-lint/)
[![Python](https://img.shields.io/pypi/pyversions/grafana-alert-lint.svg)](https://pypi.org/project/grafana-alert-lint/)

Alerting rules are code, but people review them by eye and by asking "did the
message actually arrive?". `galint` reads provisioned Grafana alerting rules and
finds the ones that survive deployment and are invisible in the UI: rules that
**look like they work and don't**.

```console
$ galint tests/fixtures/regression-0003.yml
tests/fixtures/regression-0003.yml:niki-server/Node exporter недоступен: error GAL001 noDataState=Alerting при сравнении в PromQL 'up{job="node"} == 0': Grafana считает пустой результат тревогой, а сравнение как раз создаёт пустоту, когда условие не выполнено, — такое правило не закрывается само. Если это осознанный алерт на отсутствие данных, используйте --ignore GAL001

ошибок: 1, предупреждений: 0
```

That is a real rule from an incident write-up (the fixture ships in the repo, so
the output is reproducible byte for byte). Note that 0.1.0 prints messages in
Russian; English messages are planned for 0.2.0.

## Where it came from

Two mistakes on a live server, each of them a day or two of noise in the on-call
channel. Full write-ups:
[0003](https://github.com/RealNikiHere/niki-prod/blob/main/docs/postmortems/0003-2026-11-24-alert-stuck-firing.md)
and
[0004](https://github.com/RealNikiHere/niki-prod/blob/main/docs/postmortems/0004-2026-11-24-planned-outage-alert-storm.md).

**1. `up{job="node"} == 0` with `noDataState: Alerting`.** While the server is
healthy, this expression returns not zero but **nothing**: the `up=1` series is
filtered out. Grafana sees an empty result, and `noDataState: Alerting` turns
emptiness into an outage. The rule fires forever and can never resolve —
`Resolved` never comes. The "stop the exporter" test passed, by the way: stop it
— `Firing`, start it — `Resolved`. The monitoring worked exactly backwards.

**2. `<` inside an annotation.** Grafana sends Telegram notifications with
`parse_mode=HTML`. The `<` starts a tag, Telegram answers `400`, the alert fires
and is **lost**: the error only shows up in the Grafana logs. The rule was fine;
the message never arrived.

Both problems are detectable statically, without a live Grafana.

## Install

```bash
pipx install grafana-alert-lint
# or
pip install git+https://github.com/RealNikiHere/grafana-alert-lint
```

## Usage

```bash
galint path/to/alert-rules.yml            # one file
galint metrics/grafana/provisioning/      # directory, recursively
galint rules/ --format json               # for CI and parsing
galint rules/ --opinionated               # plus style checks (GAL002/004/008/009/010/011)
galint rules/ --strict                    # warnings are errors
galint rules/ --max-file-size 0           # no size limit (4 MiB by default)
galint rules/ --ignore GAL001             # do not count GAL001 as a finding
python -m grafana_alert_lint rules/       # without the entry point
```

By default the linter stays quiet about matters of taste: no `for`, no
`severity`, `for` shorter than the evaluation step. On somebody else's
repository that is dozens of warnings with the real finding drowned in them, so
those checks have to be asked for explicitly.

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | no errors (warnings alone do not fail the run) |
| `1` | at least one error; or warnings under `--strict` |
| `2` | some paths could not be read: missing file, broken YAML, no permissions, size limit exceeded |

With code `2` the report for the files that *were* read is still printed, and
the reasons go to stderr, so CI can tell "rules are syntactically broken" from
"rules are semantically broken". To fail the build on errors only, plain
`galint rules/` is enough.

In GitHub Actions:

```yaml
- run: pipx install grafana-alert-lint && galint deploy/grafana/alerting/
```

`--format json` emits `{errors, warnings, path_errors, findings[]}` — for CI
parsing and for `grep`-ing by check code.

## What it checks

| Code | Level | Check |
|------|-------|-------|
| GAL001 | error | `noDataState: Alerting` together with a filtering PromQL comparison (`==`, `!=`, `>`, `<`, `>=`, `<=` without the `bool` modifier): on a healthy service the series is filtered out, the result is empty = permanent `Firing` |
| GAL002 | warning † | `noDataState: NoData`: a planned metrics gap (sleep, maintenance) looks like an outage |
| GAL003 | error | `noDataState` missing or unknown (Grafana accepts `OK`, `Alerting`, `NoData`, `KeepLast`) |
| GAL004 | warning † | no `for`, or the value is not a Grafana duration — fires on the first miss |
| GAL005 | error | `<` in an annotation: Telegram `400` under `parse_mode=HTML`, the message is lost (`>` is harmless) |
| GAL006 | error | `condition` missing, pointing at an unknown `refId`, or `data` is empty |
| GAL007 | error | duplicate `uid` within an organisation — provisioning silently overwrites a rule |
| GAL007 | warning | duplicate `title` within (organisation, folder): before Grafana 11.6 provisioning rejects it, from 11.6 on it is allowed but the rules land in one notification group |
| GAL008 | warning † | no `labels.severity` — nothing to route by |
| GAL009 | warning † | no `annotations.summary` — the message has no substance |
| GAL010 | warning † | no `execErrState`, or an unknown value |
| GAL011 | warning † | `for` shorter than the group interval (1 minute when `interval` is absent) — debounce shorter than the evaluation step |
| GAL012 | error | a rule with neither `uid` nor `title` — impossible to find or mute |
| GAL013 | error | the group `interval` is not a Grafana duration, or is not greater than zero |

† — style check: silent without `--opinionated`. It is about alerting quality,
not about broken provisioning.

The uniqueness scopes come from Grafana itself: `uid` is unique within an
organisation (`orgId`), `title` — within an organisation and folder (`folder`).
The same `uid` in `orgId: 1` and `orgId: 2` is fine; the same rule `title` in
different folders is a different rule. Durations are parsed like Grafana does:
integer parts only (`1h30m` is fine, `1.5s` is not).

Checks read the provisioning structure (`groups[].rules[]`) — the same shape the
Grafana API returns and that lives under `provisioning/alerting/`.

## What it does NOT check

Honestly, because the rest is not static analysis:

- whether a metric exists and whether its labels are right (needs a live
  Prometheus);
- whether routing is correct: contact points, mute timings, delivery;
- whether a rule fires on a healthy service because of a wrong threshold — that
  is established by experiment, not by a linter;
- dashboards and access control;
- Grafana-managed recording rules (`record:` in a group item): alert checks do
  not apply to them (they have no `condition`/`noDataState`), but `uid`
  uniqueness does — Grafana needs it within an organisation;
- `title` uniqueness for Grafana 11.6 and newer: the constraint was removed in
  [PR #102067](https://github.com/grafana/grafana/pull/102067), so a duplicate
  `title` is a warning (GAL007), not an error. For 11.5 and older it is a
  provisioning error — the same GAL007;
- emptiness that arises without a comparison (`absent(...)`, an empty vector
  matcher) — GAL001 looks specifically for a comparison in the expression text,
  and does not count as a comparison a string inside a label matcher, a raw
  string in backticks, or a comparison with the `bool` modifier (that one
  returns 0/1 for every series);
- which metric value counts as healthy. `up == 0` and `up == 1` are both
  comparisons and both a reason to look at the rule, but they break differently
  (empty result versus permanent `Firing`). GAL001 does not guess a side: it
  says "there is a comparison here, check the threshold against the live
  service";
- whether this is a deliberate "alert on absence". `sum(up) < 1` or `up == 0`
  with `noDataState: Alerting` is a legitimate pattern ("alert when the data is
  gone"): the empty result *is* the signal. Such a rule will honestly get
  GAL001; it is not a mistake — add `--ignore GAL001` (or keep such rules in a
  separate run).

For PromQL there is `promtool check rules`, for dashboards — `grizzly`. `galint`
complements them rather than replacing them: it is about alerting semantics, not
about syntax.

The tool is meant to be run locally against your own rules: a file is read whole
and parsed with `yaml.safe_load_all` only (no code execution); stdin
(`galint -`) is not supported. YAML parsing amplifies memory roughly 70–80×
against the file size, so files above 4 MiB are rejected by default
(`--max-file-size`, `0` disables the limit). Real provisioning files are
kilobytes; 4 MiB is already ~300 MB of memory.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest && ruff check .
```

The fixture `tests/fixtures/regression-0003.yml` is a real rule from the
incident; a test requires the linter to fail on it. CI additionally checks that
`galint` exits `1` on that fixture and `0` on the clean one.

## License

Apache-2.0 — usable in a corporate environment, with an explicit patent grant.
See [LICENSE](LICENSE).
