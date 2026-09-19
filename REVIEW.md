# Independent review — payload-guard

Three reviewers, no shared context, each with a different lens, plus Hermes' own scanner
(`hermes plugin-guard scan`). Run 2026-09-19/20 against `guard.py` / `__init__.py` /
`pin_limits.py` as they stood that morning, with the Hermes source tree
(`~/.hermes/hermes-agent`, v0.21.3 @ `5a0c2fb89e`) as the contract of record.

**33 findings: 11 security/leakage, 11 host-contract, 11 trust-model.** Nine were high.

| Severity | Count | Fixed | Partially fixed | Deferred |
|---|---|---|---|---|
| high | 9 | 9 | 0 | 0 |
| medium | 14 | 11 | 3 | 0 |
| low | 10 | 9 | 1 | 0 |

Verified afterwards: **58/58 tests pass**; the vendored pin is reproducible from the published
dataset; the plugin loads and fires against the live install (state file now records
`coverage`, and the new `api_request_error` surface counts `missed_walls`).

## What the reviewers could not break (verified clean)

- **No conversation content is logged or persisted.** Every hot-path log line passes counts,
  provider/model ids and pin text only; the live state file was read end to end (no base64, no
  stored string over 61 chars).
- **No process execution, no eval/exec, no deserialisation.** `subprocess` is gone entirely
  (the git call was replaced by reading `.git/HEAD`), and the JSON files are read with
  `json.loads` with no parse hooks, so the dataset cannot execute code: its worst case is a
  wrong number, a silent abort or text injection.
- **Exceptions cannot escape into the agent loop** — host isolation plus our own guards;
  injected `OverflowError`/`ValueError`/`AttributeError`/`RecursionError` never escaped.
- **Hook signatures, identifier pairing and middleware contract** match the real call sites;
  the plugin correctly refuses to measure the hook's *sanitised* payload instead of the raw
  `request_messages`.
- **Metering basis is never mixed**: encoded-basis limits are only ever compared against
  base64-escaped bytes, decoded against decoded, counts against counts.
- **Registration is safe to repeat**, and `_PENDING`/`_LAST`/state history are all bounded.

## The two findings that broke the plugin's core promise (both fixed)

1. **Anthropic `tool_result` images were invisible.** On the `anthropic_messages` wire a tool
   result's images sit inside `tool_result.content`; the walk only looked at the top level, so
   `images=0 / item_bytes=0` and the verdict printed **"OK — inside every measured ceiling"**
   for a payload Anthropic answers with a 400. A long tool loop with screenshots is exactly
   this shape. Fixed by recursing into `content` / `parts` / `functionResponse` containers
   (depth-capped), with a regression test that mirrors the converter's shape.

2. **Shrink mode could delete the user's own uploads.** `drop_oldest_images` protected only the
   last message, so in a tool loop the live user message holding the photos was fair game — it
   removed **all 24 of 24** where the target called for 4, contradicting both its docstring and
   the host's explicit "never rewrite user uploads" eviction policy. Fixed: `user`-role
   messages are never touched (only tool-result carriers, oldest first), removals stop the
   moment the count fits (no whole-message stripping), and the rewrite now happens on our own
   copy so the host's shallow-copy fallback cannot leak edits into the stored transcript.

## Everything else that was wrong, and what changed

**Trust model (`limits.pin.json` is third-party input).**
- A pin that *parsed* but had the wrong shape enforced **nothing, silently**, while still
  printing ceilings. `load_pin` now validates structure and `pin_version`, coerces every value
  to a finite number per key, and reports `pin-invalid` — never `ok`.
- **"No measured row" and "no numeric ceiling" printed as OK.** `Report` gained an explicit
  `coverage`, and `worst` can now be **UNKNOWN**; the CLI verdict, the status line, the state
  detail and the log all say why nothing was checked. An unsized image or a truncated body
  measurement also degrades the verdict instead of passing as verified.
- **Bracketed and documentation numbers were labelled `resolved_cap`** and enforced as hard
  breaches (an exit code a script could gate on) for sizes no probe ever rejected. The pin
  builder now derives the kind from the evidence: ollama-cloud's body cap is `[bracket]` and
  alibaba's per-item number is `[bracket]` (its note already said both readings fit), while
  the walls a probe actually hit — including the DashScope 250-item count cap — stay hard.
- **Token budgets were rendered in MiB**, so a breach showed `1.0 MiB vs 1.0 MiB` and the
  exceedance vanished; and a prefix model match suppressed the "measured on a different model"
  caveat. Tokens are now counts everywhere and the token verdict requires an exact model match.
- **The `accepted_max` advisory fired on ordinary text** (upstage: "vs limit 109 B" — a
  3-row probe artifact, not a ceiling). It now skips capability-only rows and rows whose probes
  never carried a real body, and it is worded as "largest accepted body this row observed".

**Security / robustness.**
- Payload traversal had no cycle guard and no node budget: one non-tree payload spun the hook
  worker at 100% forever and blocked every later call (the host abandons timed-out hook workers
  without joining). Now path-based cycle detection plus a node budget; a truncated or cyclic
  measurement sets `body_incomplete` and is reported as **UNKNOWN**, never as a ceiling.
- State writes followed symlinks and shared one predictable temp name — a pre-planted symlink
  made a recorded breach an arbitrary-file clobber. Now: symlink and non-regular-file refusal,
  `O_EXCL|O_NOFOLLOW` on a pid/random temp, `0600` file, `0700` directory, `os.replace`, and an
  `flock` around every read-modify-write.
- `import pin_limits` was a bare top-level import, which **cannot resolve** under the real
  plugin loader (it never puts the plugin dir on `sys.path`): the documented `pin` action was
  dead, and in the CLI path it raised a traceback. Relative import now, CLI entry point wrapped,
  and the rebuild's exit code is checked instead of reporting success unconditionally.
- Pin text is sanitised before it reaches a log line, the state file or the terminal (control
  characters and newlines stripped, length capped).
- `status`/`check`/`providers` read the *configured* state and pin files — they used to answer
  from the defaults while the hook wrote elsewhere, so a configured path produced "no findings
  recorded yet" as pure false assurance.
- `load_config()` (a full deepcopy) was called 1–3× per API call on the hot path; now the
  read-only accessor is preferred.
- The data-URI regex matched against a whole string; a huge `data:`-prefixed non-URI cost a
  full backtracking scan. Now matched against a bounded head.

**Calibration.**
- The ledger was one-directional: `post_api_request` only fires on success, so a **false
  negative left no record at all** and the state file could only ever look healthy. The plugin
  now registers `api_request_error` and records `missed-wall` (no wall predicted, provider
  refused) versus `rejected-as-predicted`.
- `--check` is no longer conflated with a rewrite that fitted: the middleware logs "rewrote the
  outgoing payload to fit" only when the post-action measurement actually fits, and says
  "STILL over a measured wall" otherwise.

## Residual risk you should keep in mind

**Closed 2026-09-20 (the two called out after the review):**

- **The body figure now says what it covers.** `Measure.body_scope` is `whole-request` on the
  request-dict surface (it measures the dict Hermes is about to serialise -- system prompt and
  tool schemas included, transport kwargs such as `timeout` excluded), `messages+system` on
  the pre-flight hook, and `messages` for the CLI's user-supplied figures. Every `BODY` finding
  carries the scope in its note, and when the scope is partial and the figure sits at 75-100% of
  a body ceiling the verdict is **advisory, not OK**: that close to the wall the missing tool
  schemas are exactly the difference that matters.
- **The host is part of the measurement's scope.** `resolve()` compares the row's `host` with the
  hook's `base_url`; a request that did not go to the measured host is reported **UNKNOWN**
  (`coverage: host-mismatch`), never as a fit or a breach. A proxy or a regional endpoint now
  degrades the verdict instead of silently borrowing a ceiling.
- **Alias coverage: 23 of 34 canonical names now reach a row with limits** (was 16 of ~72),
  9 reach a row without limits (honest UNKNOWN), 2 reach no row at all. Added: `github-copilot`,
  `kimi-for-coding`, `kimi-coding-cn`, `deep-infra`, `deepinfra-ai`, `qwen-oauth`, `qwencloud`,
  `dashscope-cn`, `alibaba-cloud-cn`, `minimax-oauth`, `nebius`, `token-factory`, `openai-api`.
  Canonicalisation is a **fallback, never a shadow**: Hermes maps the bare name `openai` to
  `openrouter`, and following that first would have dropped the openai row -- the best-measured
  wall in the set.
- **Provenance is checkable.** The pin carries `dataset_sha256` (the published `limits.json`) and
  `builder_sha256` (`pin_limits.py`), and `status` prints the pin's own sha256 as loaded, so the
  chain dataset -> builder -> pin can be verified by hand. `pin_limits.py --check` re-derives the
  pin and names any drift.
- **One code path decides.** `g.assess()` is shared by the live hooks and the CLI, and
  `_handle_cli` forwards everything argparse parsed. The three surfaces used to disagree -- and
  did -- so the single decision point is the fix, not a copy kept in step by hand.

**Still open:**

- **The rewrite surface was removed in 1.1.0.** `mode: shrink` was never proven against a live
  provider rejection, and the plugin's brief was observe-and-warn, so publishing it would have
  shipped an unproven payload-rewriting path in a trust-signal catalog. The implementation and
  its tests are preserved on the `shrink-mode` branch; setting `mode: shrink` now logs a warning
  and runs warn-only. This is also what took the scanner from `high=1` to `high=0`.
- **A documented-only row can still read `ok`** when the request is inside the vendor's stated
  number (e.g. `xai`). The number is advisory, not a measurement, and the row says so.
- **Provenance is self-asserted.** The hashes make the chain checkable, but nothing signs the
  dataset, `limits_commit` and `pinned_at` still come from the local copy, and re-pinning from
  the network is deliberately not done.
- **`tool_count` does not become bytes.** The hook cannot see the tool schemas, so a
  partial-scope figure stays a lower bound rather than a guess at their size.

## Scanner status

`hermes plugin-guard scan` reports **medium=1, PASS** for v1.1.0. `HPG110` (the privileged
`llm_request` middleware) was resolved by removing the rewrite path, exactly as this section
recommended while the finding was open. The remaining finding is accepted:

- `HPG108` — `os.unlink()` in the temp-file cleanup path. Confined to a file this plugin just
  created with `O_EXCL` inside the resolved state directory, guarded by an explicit
  parent/name/symlink check; it removes only our own litter.

## Reproducing

- Scanner: `hermes plugin-guard scan /home/dan/.hermes/plugins/payload-guard`
- Tests: `.venv/bin/python -m pytest tests/ -q` (65 tests)
- Pin drift: `python3 pin_limits.py --check`
- Reviewer transcripts:
  `/home/dan/.hermes/cache/delegation/live/deleg_6ce1867f/task-{0,1,2}.log`
  (full findings, with the PoCs each reviewer ran under `/tmp`).
