#!/usr/bin/env python3
"""audit-gate — gate a security-audit run on its machine-verifiable artefacts.

Validates findings.json and coverage-ledger.json against the schema and validators
shipped with the `security-audit` skill (Cloudflare security-audit-skill, MIT).

Why a wrapper and not just the validators: a run can fail in three different ways and
they must never collapse into one message (see the `auditing-automation` skill).

  VALID    0  artefact present, schema + validators agree
  INVALID  1  artefact present, validation failed (the gate fires)
  MISSING  2  no artefact found — the run never produced one, or was never run;
              this is an alarm, NOT a pass
  BLOCKED  3  node/skill/validators unavailable — "could not look", also not a pass

Usage:
  audit-gate [--json] [--skill-dir DIR] [TARGET]

TARGET is a run directory containing the artefacts, or a tree to search (depth 3).
Defaults to the newest run under ~/security-audit-skill/*/run-*.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

VALID, INVALID, MISSING, BLOCKED = 0, 1, 2, 3
STATUS = {VALID: "VALID", INVALID: "INVALID", MISSING: "MISSING", BLOCKED: "BLOCKED"}

ARTEFACTS = (("findings", "findings.json", "validate-findings.cjs"),
             ("ledger", "coverage-ledger.json", "validate-coverage-ledger.cjs"))

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache"}


def newest_run(home: Path) -> Path | None:
    root = home / "security-audit-skill"
    if not root.is_dir():
        return None
    runs = [p for p in root.glob("*/run-*") if p.is_dir()]
    if not runs:
        runs = [p for p in root.glob("run-*") if p.is_dir()]
    if not runs:
        return None
    return max(runs, key=lambda p: p.stat().st_mtime)


def find(target: Path, name: str) -> Path | None:
    direct = target / name
    if target.is_file() and target.name == name:
        return target
    if direct.is_file():
        return direct
    for base, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        if base.count(os.sep) - str(target).count(os.sep) > 3:
            dirs[:] = []
            continue
        if name in files:
            return Path(base) / name
    return None


def run_validator(validator: Path, artefact: Path) -> tuple[int, str]:
    proc = subprocess.run([shutil.which("node") or "node", str(validator), str(artefact)],
                          capture_output=True, text=True, timeout=300)
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out.strip()


def main() -> int:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("target", nargs="?", help="run dir or tree to search")
    ap.add_argument("--json", action="store_true", dest="as_json")
    ap.add_argument("--skill-dir", default=str(Path(__file__).resolve().parent))
    args = ap.parse_args()

    report: dict = {"artefacts": {}, "status": None, "detail": ""}

    skill = Path(args.skill_dir).expanduser()
    scripts = skill / "scripts"
    node = shutil.which("node")

    target = Path(args.target).expanduser().resolve() if args.target else newest_run(Path.home())
    if target is None:
        report["status"] = "MISSING"
        report["detail"] = "no target given and no run found under ~/security-audit-skill"
        emit(report, args.as_json)
        return MISSING
    if not target.exists():
        report["status"] = "MISSING"
        report["detail"] = f"target does not exist: {target}"
        emit(report, args.as_json)
        return MISSING

    missing = [n for _, n, _ in ARTEFACTS if find(target, n) is None]
    if len(missing) == len(ARTEFACTS):
        report["status"] = "MISSING"
        report["detail"] = f"no findings.json or coverage-ledger.json under {target}"
        emit(report, args.as_json)
        return MISSING

    if node is None or not (scripts / "validate-findings.cjs").is_file():
        report["status"] = "BLOCKED"
        report["detail"] = ("node not on PATH" if node is None
                            else f"validators not found in {scripts}")
        report["target"] = str(target)
        emit(report, args.as_json)
        return BLOCKED

    codes = []
    for key, name, script in ARTEFACTS:
        artefact = find(target, name)
        if artefact is None:
            report["artefacts"][key] = {"path": None, "status": "MISSING"}
            codes.append(MISSING)
            continue
        code, out = run_validator(scripts / script, artefact)
        report["artefacts"][key] = {
            "path": str(artefact),
            "status": "VALID" if code == 0 else "INVALID",
            "validator_exit": code,
            "output": out.splitlines()[:20],
        }
        codes.append(VALID if code == 0 else INVALID)

    worst = BLOCKED if BLOCKED in codes else (INVALID if INVALID in codes else
                                              (MISSING if MISSING in codes else VALID))
    report["status"] = STATUS[worst]
    report["target"] = str(target)
    report["detail"] = "; ".join(f"{k}={v['status']}" for k, v in report["artefacts"].items())
    emit(report, args.as_json)
    return worst


def emit(report: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, sort_keys=True))
        return
    print(f"audit-gate: {report['status']} — {report.get('detail', '')}")
    for key, info in report.get("artefacts", {}).items():
        path = info.get("path") or "-"
        print(f"  {key:8s} {info['status']:7s} {path}")
        for line in info.get("output", []):
            print(f"      {line}")


if __name__ == "__main__":
    sys.exit(main())
