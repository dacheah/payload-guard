# audit-gate

Gates a security-audit run on its **machine-verifiable artefacts** rather than on prose: a run's
`findings.json` and `coverage-ledger.json` must validate against the schema and validators before
anything downstream accepts them.

Vendored from [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)
(MIT — see `LICENSE.cloudflare`), the same skill this profile runs audits with. Only the two
zero-dependency validators, their schema and this wrapper are vendored; the upstream fixture suites
(34 + 31 assertions) stay with the skill.

## States — never collapsed into one message

| Exit | State | Meaning |
|-----:|-------|---------|
| 0 | `VALID` | Artefact present; schema and validators agree |
| 1 | `INVALID` | Artefact present; validation failed — the gate fires |
| 2 | `MISSING` | No artefact found. The run never produced one, or never ran — an alarm, **not** a pass |
| 3 | `BLOCKED` | node or the validators are unavailable — "could not look", also not a pass |

## Use

```bash
python3 tools/audit-gate/audit-gate.py path/to/run-dir          # human output
python3 tools/audit-gate/audit-gate.py --json path/to/tree      # one-line JSON verdict
python3 tools/audit-gate/self-test.sh                           # proves all four states
```

`TARGET` is a run directory holding the artefacts, or a tree to search (depth 3). `--skill-dir`
overrides where the validators are found; it defaults to this directory. No target given looks for
the newest run under `~/security-audit-skill/*/run-*`.

## What CI does with it

`.github/workflows/audit-gate.yml` runs on every push and pull request:

1. **`self-test.sh`** — asserts exit 0/1/2/3 on the bundled fixtures. This is what keeps the gate
   honest: it exercises its own failure paths whether or not the repository holds an audit artefact.
2. **Real artefacts** — validates any `findings.json` / `coverage-ledger.json` in the tree.
   Exit 1 fails the job. With no artefact present the step reports exit 2 as a distinct, visible
   state and does not fail — the gate holds no verdict because there is nothing to gate.

## Fixtures

- `selftest/valid/findings.json` — one complete `confirmed` record; `coverage-ledger.json` is the
  minimal accepted ledger (`[]`).
- `selftest/invalid/` — the same record with `trace` removed (schema failure), plus a malformed
  ledger; both validators are exercised in the failing direction.

The ledger validator's deeper rules (canonical coverage ids, evidence states) are covered by the
upstream suite, not by these fixtures.
