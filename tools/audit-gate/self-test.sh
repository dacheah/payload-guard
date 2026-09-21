#!/usr/bin/env bash
# Self-test for the audit gate: proves all four exit states on every CI run, so the
# gate cannot sit dormant and green. Mirrors the `auditing-automation` rule that a
# check is worth exactly what its last real run proved.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
gate="python3 $here/audit-gate.py"
fail=0

expect() { # label expected_exit actual_exit
  if [ "$2" = "$3" ]; then
    echo "ok   - $1 (exit $3)"
  else
    echo "FAIL - $1: expected exit $2, got $3"
    fail=1
  fi
}

run() { # args... -> prints exit code
  $gate "$@" >/dev/null 2>&1
  echo $?
}

expect "valid artefacts pass"            0 "$(run "$here/selftest/valid")"
expect "invalid artefacts fail the gate" 1 "$(run "$here/selftest/invalid")"
expect "absent artefacts are MISSING"    2 "$(run "$here/selftest/absent")"
expect "no validator available is BLOCKED" 3 \
  "$(run --skill-dir "$here/selftest/absent" "$here/selftest/valid")"

if [ "$fail" -ne 0 ]; then
  echo "audit-gate self-test: FAILED"
  exit 1
fi
echo "audit-gate self-test: all four states behave"
