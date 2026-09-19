# Add payload-guard to the plugin catalog

`payload-guard` pre-flights the request Hermes is about to send against the **empirically
measured** payload ceilings of the provider it is going to — body bytes, total and per-image
bytes, image count, input-token budget — and warns before the call is spent.

The data is [github.com/dacheah/payload-walls](https://github.com/dacheah/payload-walls): 20
providers probed against live keys, one dated row per measured ceiling, 540 probe rows. Several
of those numbers are only knowable by measurement — OpenAI's documented image envelope and its
enforcement have disagreed since April, and DashScope rejects a 251st data-URI item with wording
that no "image" keyword classifier catches.

**Warn-only.** The plugin registers three hooks (`pre_api_request`, `post_api_request`,
`api_request_error`), no middleware and no tools, and cannot rewrite a payload. It records each
measured call — with the coverage it had — to `~/.hermes/payload-guard/state.json` so "checked
and fine" stays distinguishable from "not checked".

What makes its verdicts trustworthy, and what a reviewer should check:

* **Three outcomes, not two.** Inside a measured ceiling, outside it, or *not checked* — an
  absent or unknown row renders UNKNOWN, never "ok".
* **Scope is stated.** A body ceiling is a whole-request number; when the surface cannot see the
  tool schemas the figure is labelled a lower bound, and inside 75–100% of a body ceiling the
  verdict becomes *advisory* rather than OK.
* **The measured host is part of the ceiling.** A request that went somewhere else (proxy,
  regional endpoint) is UNKNOWN rather than borrowing a number.
* **Only numbers a probe actually hit may fail a request.** Documented/bracket numbers are
  advisory and are labelled as such.

Entry validation:

* `hermes plugins validate <dir>` at the pinned commit → **passed**, no warnings.
* `hermes plugin-guard scan <dir>` → **high=0, medium=1, PASS**. The one medium is a temp-file
  unlink in the state write, confined to a file the plugin created with `O_EXCL`/`O_NOFOLLOW`
  inside its own state directory; it is documented in `SECURITY.md`.
* Exact pin: commit `093f00d2834620bb832d068152861b97ea4995da` (tag `v1.1.0`).
* No network calls, no process execution, no self-updater — the dataset is vendored as a dated,
  hash-verified copy (`limits.pin.json`), and provenance is read from `.git/HEAD` rather than
  shelling out to `git`.
* 55 tests, most replaying real probe rows (same image sizes, same counts, same
  accept/reject outcome), so a regression shows up as a disagreement with measured ground truth.

MIT licensed. `SECURITY.md` records every accepted scanner finding with its rationale;
`REVIEW.md` is the three-lens review (correctness, honesty, robustness) and its residual risk.

Platforms: Linux, tested. macOS/Windows are untested rather than refused, which is why
`platforms:` in the manifest still says `linux`.
