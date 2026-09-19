# Security notes — payload-guard

A local Hermes Agent plugin. It measures the request Hermes is about to send and compares
it against the provider payload ceilings published at
<https://github.com/dacheah/payload-walls> (vendored, dated, as `limits.pin.json`).

## What it touches

| Surface | Detail |
| --- | --- |
| Hook `pre_api_request` | Reads the outgoing payload to measure it. Returns nothing that changes the request. |
| Hook `post_api_request` | Records whether a prediction the plugin made was contradicted by the provider. |
| Middleware | **None.** v1.1.0 registers no middleware, so the plugin has no way to alter a payload. (Up to v1.0.1 a `llm_request` rewrite path existed behind `mode: shrink`; it is preserved on the `shrink-mode` branch, not in this release.) |
| Reads | `limits.pin.json`, `aliases.json` (its own directory); the pin is plain JSON, no code, no network. |
| Writes | `~/.hermes/payload-guard/state.json` (or `$HERMES_PAYLOAD_GUARD_STATE`) — counters plus, for non-OK verdicts, `provider`, `model`, `pin_key`, the wall key breached, the measured figure and the limit, and a free-text note. Message text, tool output, URLs, prompts and credentials are never written. |
| Network | None. The plugin never makes a request; the dataset is vendored on purpose so a guard cannot be steered by a live fetch. |
| Process execution | None. `git` is not shelled out to; provenance is read from `.git/HEAD` as a file. |
| Imports | Stdlib plus the plugin's own `guard` module. No `eval`/`exec`/`pickle`. |

## What it will not do

- Never raises into the agent loop: every hook body is wrapped, and a failure
  degrades to "no measurement" rather than a broken turn.
- Never logs or persists conversation content, credentials, or file contents. Log lines carry
  sizes (`body=478.7 KiB`), counts and provider names only.
- Never claims a ceiling it did not measure: rows that are brackets, documentation-only, or
  unmeasured are rendered as such, and "no limit known" is never shown as "OK".

## Review status

- `hermes-plugin-guard` 0.2.1 (`hermes plugin-guard scan .`) is run against this directory;
  findings and their resolution are recorded in the run log kept alongside the plugin.
- HPG110 ("privileged plugin surface") was the `llm_request` middleware, and it is **gone**: the
  rewrite path was removed in v1.1.0. The scanner now reports `medium=1` and **PASS**; the one
  remaining finding is the bounded temp-file cleanup described below.
- Independent review passes (security/leakage, host-contract correctness, trust model of the
  pinned dataset) were run on 2026-09-20; their findings and fixes are in `REVIEW.md`.

## Reporting

Open an issue at <https://github.com/dacheah/payload-guard>. Dataset corrections belong upstream
at <https://github.com/dacheah/payload-walls>. Do not include real request payloads or
credentials in a report; a size, a provider, a model and the wall key are enough to reproduce.

Supported versions: the latest tagged release. There are no maintenance branches and no
maintained branches — the copy in `~/.hermes/plugins/payload-guard/` is the only copy.

## Scanner findings (v1.1.0, reviewed 2026-09-20)

`hermes plugin-guard scan` reports **medium=1, PASS** (`high=0`). v1.0.1 carried a second,
`high` finding — the payload-rewriting `llm_request` middleware — which the 1.1.0 removal of
that path resolved outright. See `REVIEW.md` for the full independent review (33 findings, all
triaged; it was run against the v1.0.1 snapshot and its fixes are all in this release).
- **HPG108 — `os.unlink()` in the state write.** The only unlink in the plugin, confined to the
  temp file the same function just created with `O_CREAT|O_EXCL|O_NOFOLLOW` inside the resolved
  state directory, behind an explicit parent-equals-target-parent / name-prefix / not-a-symlink
  check. It cannot reach a file the plugin did not create.
