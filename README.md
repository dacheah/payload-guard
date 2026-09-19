# payload-guard

A Hermes plugin that checks the request Hermes is about to send against the **empirically
measured** payload ceilings of the provider it is actually going to — body bytes, total image
bytes, per-image bytes, image count, input-token budget — and warns *before* the call is spent.

The numbers come from [github.com/dacheah/payload-walls](https://github.com/dacheah/payload-walls):
20 providers, probed against live keys, one row per measured ceiling, every row dated. They are
not vendor doc claims, and where a vendor's docs disagree with its enforcement, the dataset
carries both.

```
$ hermes payload-guard status
payload-guard 1.1.0 — mode warn
pin      : 20 providers, dataset 2026-09-19T11:56:24+00:00, pinned 2026-09-19T21:11:09+00:00
...
```

## What it does, and what it deliberately does not

* Registers the `pre_api_request`, `post_api_request` and `api_request_error` hooks.
* **Warn-only.** It measures the real outgoing request and logs what it finds. It never
  rewrites, truncates or drops anything from your payload.
* Records every measured call to a state file (`~/.hermes/payload-guard/state.json`) with the
  coverage it had, so "checked and fine" is distinguishable from "not checked".
* Calibrates: if a call the plugin predicted would fail came back fine, that is recorded as a
  false positive rather than silently discarded. A prediction that failed shows up under
  `missed_walls`.
* Slash command `/payload-guard` and CLI `hermes payload-guard` with `status`, `check`,
  `providers`, `pin` and `false-positive`.

The payload-rewriting middleware that used to exist behind `mode: shrink` is **not** in this
release; it was never proven against a live provider rejection and the plugin's brief is
observe-and-warn. It lives on the `shrink-mode` branch. Setting `mode: shrink` in config logs a
warning and runs warn-only.

## The four rules that make a verdict trustworthy

1. **Three outcomes, not two** — inside a measured ceiling, outside it, or *not checked*.
   An unusable/absent row renders as UNKNOWN; it never renders as "ok".
2. **Scope is stated, and a partial figure is a lower bound.** A body ceiling is a
   whole-request number. The `pre_api_request` hook cannot see the tool schemas, so when its
   body figure is partial the report says so — and inside 75–100% of a body ceiling the verdict
   becomes *advisory*, because at that distance the unseen tool schemas are the difference that
   matters.
3. **Host is part of the ceiling.** The row's measured host is compared against the request's
   `base_url`; a request that did not go to the measured host is UNKNOWN, rather than borrowing
   a number measured somewhere else.
4. **Only a number a probe actually hit may fail a request.** Measured rows are hard walls.
   Documented or bracket numbers (`largest accepted`) are advisory and are labelled as such.

## Install

```bash
hermes plugins install dacheah/payload-guard --enable
```

Config (`config.yaml` → `plugins.entries.payload-guard`), all keys optional:

```yaml
plugins:
  entries:
    payload-guard:
      enabled: true
      mode: warn            # warn | off
      log_calls: false      # info-log every measured call
      token_warn_ratio: 0.9 # warn at 90% of a token budget
      pin_path: ""          # override the vendored limits.pin.json
      state_path: ""        # override ~/.hermes/payload-guard/state.json
```

## The dataset, and its expiry date

`limits.pin.json` is a **dated copy** of the published dataset, vendored so the plugin cannot
silently drift with a remote file:

| field | value |
| --- | --- |
| providers | 20 |
| rows | 540 |
| measured | 2026-09-19T11:56:24+00:00 |
| dataset commit | `a8ccd8050a60504a9ca6566263f5f9affcff41f4` |
| dataset sha256 | `e95e6f4d65a5b2b9717cba8642e674e3512fe9c5ff81fa9cd370b451640d781a` |
| builder sha256 | `a0d117ec6a5ccf4e67367f4ac8a9c5e14e176f0c08c749b11e2d77fb154f010a` |

Refresh it against your own copy of the dataset:

```bash
python pin_limits.py /path/to/limits.json   # rebuild limits.pin.json
python pin_limits.py --check                # verify it is current, and reproducible
```

`PAYLOAD_WALLS_JSON` / `PAYLOAD_WALLS_REPO` point at a checkout instead of passing a path.

Every row is scoped: one provider, one model, one region, one key tier, one date. **"No cap
found" is a lower bound, never "unlimited".** A vendor changing a ceiling does not break the
plugin; it just makes the pin stale, and `--check` says so.

## Honesty about coverage

Provider names in Hermes do not map one-to-one onto the dataset's ids. `aliases.json` maps
Hermes names (including OAuth-flavoured ones like `qwen-oauth`, `xai-oauth`) onto dataset rows,
and a name with no row is reported as no row — never quietly matched to a plausible
neighbour. Canonicalisation is a fallback, never a shadow: bare `openai` must not resolve to
`openrouter`.

## Platforms

Developed and tested on Linux. macOS and Windows are untested, not refused: the state file uses
`fcntl`/`O_NOFOLLOW` where available and falls back to plain, `0600` writes.

## Security, review and tests

* `SECURITY.md` — what the plugin touches, and every accepted scanner finding with its reason.
* `REVIEW.md` — the three-lens review (correctness, honesty, robustness) and its residual risk.
* `tests/` — the interesting cases are replays of real probe rows (same image sizes, same
  counts, same accept/reject outcome), so a regression surfaces as a disagreement with ground
  truth measured against the live API.

```bash
python -m pytest tests/ -q
hermes plugins validate .        # catalog admission gate
```

MIT licensed.
