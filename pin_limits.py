"""Regenerate ``limits.pin.json`` from the published payload-walls dataset.

Usage:
    python pin_limits.py [path/to/limits.json] [--out limits.pin.json] [--check]

``--check`` exits non-zero when the pin on disk differs from what the dataset would
produce, which is what a cron job should alert on: the pin is dated, and a stale pin is
reported as stale rather than silently trusted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
def default_sources() -> List[Path]:
    """Candidate locations for the published dataset (``limits.json``).

    Regeneration only: the pin ships vendored beside this file, so anyone who never re-pins
    never touches this list. An explicit ``--source`` or ``PAYLOAD_WALLS_JSON``/``_REPO``
    override still wins.
    """
    candidates: List[Path] = []
    for raw in (os.environ.get("PAYLOAD_WALLS_JSON"), os.environ.get("PAYLOAD_WALLS_REPO")):
        if raw:
            path = Path(raw).expanduser()
            candidates.append(path / "limits.json" if path.is_dir() else path)
    candidates.append(Path.home() / "llm-request-budgets" / "limits.json")
    candidates.append(HERE / "limits.json")
    return candidates


#: Static view of the same list, for argparse help and docs.
DEFAULT_SOURCES = tuple(default_sources())
REPO = "https://github.com/dacheah/payload-walls"

#: Nuances that the raw dataset implies but a naive consumer would get wrong. Each is
#: attached to the limit it qualifies, and surfaced verbatim in reports.
LIMIT_NOTES: Dict[str, Dict[str, str]] = {
    "xai": {
        "item_bytes": "documented-only row: no API key on the measuring host, so this is NOT verified here",
    },
    "upstage": {
        "items": "the measured endpoint rejects image input outright ('Image input is not allowed for this model')",
    },
    "openai": {},
    "alibaba": {
        "items": "DashScope says 'data-uri' rather than 'image'; Hermes' own classifier misses this wording",
        "body_bytes": "no body wall found below 512 MiB accepted — treat any body limit as unknown",
    },
    "gemini": {"input_tokens": "token budget, not a byte wall; counts depend on image resolution"},
    "anthropic": {"body_bytes": "413 request_too_large; per-image cap is 10 MiB"},
    "deepseek": {"body_bytes": "48 MiB body wall; per-image 32 MiB"},
    "minimax": {"body_bytes": "128 MiB exact; per-image 10 MiB"},
    "nvidia": {"body_bytes": "25 MiB exact, stated in the error text"},
    "ollama-cloud": {"body_bytes": "bracket only (15.9-16.5 MiB) — the cap is not exact"},
}

#: Which of our figures the vendor's own counter corresponds to, plus the measured ratio
#: between them where the two differ. Derived from the probe rows cited in each note —
#: not from documentation.
LIMIT_METERING: Dict[str, Dict[str, Dict[str, Any]]] = {
    "openai": {
        "image_total_bytes": {
            "value": 50_000_000,
            "as_stated": "50MB",
            "basis": "encoded",
            "metered_factor": 1.0257,
            "note": (
                "'50MB' read as decimal. The measured pair — 17 x 2,053,887 B accepted, 18 x "
                "the same rejected with 'Total image size is 50.56MB, which exceeds the allowed "
                "limit of 50MB' — is reproduced by 50,000,000 against base64 bytes x 1.0257, and "
                "NOT by a 50 MiB reading. The vendor counts its own normalised copy, so a few "
                "very large images (8 x 12,144,445 B, accepted) pass far above this budget: those "
                "are downscaled before counting. Expect a false positive on that shape; the "
                "plugin records it."
            ),
        }
    },
    "alibaba": {
        "item_bytes": {
            "basis": "encoded",
            "note": (
                "vendor wording is 'Maximum single Base64 content: 20 MiB'; the failing rung sent "
                "20.3 MiB decoded (27 MiB encoded) so both readings fit the observation — encoded "
                "is the stricter one, and the 96-image 512 MiB run that passed stayed far below it"
            ),
        }
    },
}


def _sha256_file(path: "Path | str") -> str:
    """sha256 of a file's bytes, "" when it cannot be read.

    Recorded in the pin so the dataset behind a ceiling is identifiable, not just named: a
    reader can hash the published ``limits.json`` and compare. There is still no signature --
    the provenance is self-asserted -- but it is checkable.
    """
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except Exception:
        return ""


def _git_commit(path: Path) -> str:
    """Read the source repo's HEAD from disk.

    Deliberately does NOT shell out to git: a plugin that executes processes is a
    privileged surface (hermes-plugin-guard HPG103), and the provenance field is not
    worth that. Returns "" when it cannot be read without help.
    """
    try:
        repo, head = path.parent.resolve(), None
        while True:
            if (repo / ".git").exists():
                head = repo / ".git" / "HEAD"
                break
            if repo == repo.parent:
                return ""
            repo = repo.parent
        text = head.read_text(encoding="utf-8", errors="replace").strip()
        if not text.startswith("ref:"):
            return text  # detached HEAD: the file holds the commit itself
        want = text.split(" ", 1)[1].strip()
        ref = repo / ".git" / want
        if ref.exists():
            return ref.read_text(encoding="utf-8", errors="replace").strip()
        packed = repo / ".git" / "packed-refs"
        if packed.exists():
            for line in packed.read_text(encoding="utf-8", errors="replace").splitlines():
                if line and not line.startswith(("#", "^")) and line.rsplit(" ", 1)[-1] == want:
                    return line.split(" ", 1)[0].strip()
    except Exception:
        pass
    return ""


def _cap(limits: Dict[str, Any], key: str) -> Optional[int]:
    spec = limits.get(key)
    if isinstance(spec, dict):
        value = spec.get("value")
    else:
        value = spec
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


#: The dataset's own words for "this number is not an exact measurement". A cap carrying
#: one of these is reported as a bracket: it may still be right, but presenting it as a
#: resolved ceiling turns a guess inside a bracket into a hard "the provider will reject
#: this" claim, complete with a non-zero exit status.
_HEDGE = re.compile(
    r"bracket|not exact|both readings|vendor wording|not probed|was not probed|"
    r"no (?:body )?wall found|treat any .*? as unknown|inferred",
    re.I,
)


def _evidence_kind(entry: Dict[str, Any]) -> str:
    """Kind a limit by the evidence behind that number, not by the row's confidence.

    ``resolved_cap``/``stated_in_error`` are treated as hard by the guard; ``bracket``,
    ``documented``, ``capability`` are advisory. Demotion happens only where the dataset
    itself says the figure is not exact.
    """
    kind = str(entry.get("kind") or "")
    if kind in {"capability", "documented"}:
        return kind
    if entry.get("as_stated") is not None and not entry.get("note"):
        return "documented"
    if _HEDGE.search(str(entry.get("note") or "")) or _HEDGE.search(str(entry.get("as_stated") or "")):
        return "bracket"
    return kind or "resolved_cap"


def build(limits_path: Path, aliases: Dict[str, Any]) -> Dict[str, Any]:
    data = json.loads(limits_path.read_text(encoding="utf-8"))
    providers: Dict[str, Any] = {}
    for row in data.get("providers") or []:
        pid = row.get("id")
        if not pid:
            continue
        caps = row.get("caps") or {}
        measured = row.get("measured") or {}
        walls = measured.get("walls") or {}
        accepted = measured.get("largest_accepted") or {}
        notes = LIMIT_NOTES.get(pid) or {}

        limits: Dict[str, Any] = {}
        confidence = str(row.get("confidence") or "measured")
        hard = confidence == "measured"

        def put(key: str, value: Any, kind: str, scope: str = "provider") -> None:
            if value is None or confidence == "unmeasured":
                return
            entry = {"value": int(value), "kind": kind if hard else "documented", "scope": scope}
            note = notes.get(key)
            if note:
                entry["note"] = note
            entry["kind"] = _evidence_kind(entry)
            limits[key] = entry

        def stated(cls: str, key: str, scope: str = "provider") -> None:
            wall = walls.get(cls) or {}
            cap = wall.get("cap_stated_in_error")
            if cap is not None and key not in limits:
                put(key, cap, "stated_in_error", scope)

        if caps.get("max_items") == 0:
            put("items", 0, "capability")
        else:
            put("items", caps.get("max_items"), "resolved_cap")
        put("body_bytes", caps.get("body_bytes"), "resolved_cap")
        put("item_bytes", caps.get("per_item_bytes"), "resolved_cap")
        put("input_tokens", caps.get("token_budget"), "resolved_cap", "model")

        for cls in ("body", "edge_body_bytes"):
            stated(cls, "body_bytes")
        stated("image_total", "image_total_bytes")
        stated("item_count", "items")
        stated("item_bytes", "item_bytes")

        # Metering corrections: what the vendor's own counter saw, where it differed from
        # the bytes we sent. Applied after the dataset figures so it can override them.
        for key, extra in (LIMIT_METERING.get(pid) or {}).items():
            if confidence == "unmeasured":
                continue
            entry = limits.get(key)
            if entry is None:
                if extra.get("value") is None:
                    continue
                entry = {"kind": "stated_in_error", "scope": "provider"}
            if extra.get("value") is not None:
                entry["value"] = int(extra["value"])
            for field in ("as_stated", "basis", "metered_factor"):
                if extra.get(field) is not None:
                    entry[field] = extra[field]
            if extra.get("note"):
                entry["note"] = extra["note"]
            entry["kind"] = _evidence_kind(entry)
            limits[key] = entry

        observed_max: Dict[str, Any] = {}
        if accepted.get("body_bytes"):
            observed_max["body_bytes"] = accepted["body_bytes"]
        if accepted.get("images") is not None:
            observed_max["items"] = accepted["images"]
        if accepted.get("model"):
            observed_max["model"] = accepted["model"]

        reject_at: Dict[str, Any] = {}
        for cls, wall in walls.items():
            if wall.get("body_bytes"):
                reject_at[cls] = wall["body_bytes"]

        providers[pid] = {
            "label": row.get("provider") or pid,
            "host": row.get("host") or "",
            "wire": row.get("wire") or "",
            "measured_on": row.get("model_tested"),
            "measured_at": row.get("measured_at"),
            "binding": row.get("binding_constraint"),
            "confidence": row.get("confidence"),
            "limits": limits,
            "observed_max": observed_max,
            "observed_reject_body_bytes": reject_at,
            "notes": row.get("notes") or "",
            "documented": ((row.get("documented") or {}).get("current") or {}).get("text") or "",
        }

    return {
        "pin_version": 1,
        "pinned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": {
            "repo": REPO,
            "file": Path(limits_path).name,
            "limits_generated_at": data.get("generated_at"),
            "limits_commit": _git_commit(limits_path),
            "dataset_sha256": _sha256_file(limits_path),
            "builder_sha256": _sha256_file(Path(__file__).resolve()),
            "row_count": data.get("row_count"),
            "scope": data.get("scope") or {},
        },
        "conventions": [
            "Values are JSON request-body bytes in binary units (MiB = 1024^2).",
            "kind=resolved_cap: a squeeze run resolved the exact ceiling.",
            "kind=stated_in_error: the cap parsed out of the vendor's own rejection text.",
            "kind=accepted_max: the largest request these probes saw accepted — exceeding it is "
            "unmeasured territory, not a proven failure.",
            "One model per provider, one region, one key tier: a row is a dated sample, not a spec.",
        ],
        "aliases": aliases,
        "providers": providers,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Rebuild limits.pin.json from payload-walls limits.json")
    parser.add_argument("limits", nargs="?", help="path to limits.json")
    parser.add_argument("--out", default=str(HERE / "limits.pin.json"))
    parser.add_argument("--check", action="store_true", help="exit 1 when the pin is stale")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    candidates: List[Path] = [Path(args.limits)] if args.limits else list(DEFAULT_SOURCES)
    limits_path = next((p for p in candidates if p.is_file()), None)
    if limits_path is None:
        print("pin_limits: no limits.json found (pass a path or set PAYLOAD_WALLS_JSON)", file=sys.stderr)
        return 2

    aliases = json.loads((HERE / "aliases.json").read_text(encoding="utf-8"))
    pin = build(limits_path, aliases)
    rendered = json.dumps(pin, indent=2, sort_keys=False) + "\n"
    out = Path(args.out)

    if args.check:
        if not out.is_file():
            print(f"pin_limits: {out} missing", file=sys.stderr)
            return 1
        current = json.loads(out.read_text(encoding="utf-8"))
        # pinned_at always differs; compare everything else.
        current.pop("pinned_at", None)
        fresh = dict(pin)
        fresh.pop("pinned_at", None)
        if current != fresh:
            print(f"pin_limits: {out} is stale; rerun without --check", file=sys.stderr)
            return 1
        if not args.quiet:
            print(f"pin_limits: {out} is current ({len(pin['providers'])} providers)")
        return 0

    out.write_text(rendered, encoding="utf-8")
    with_limits = sum(1 for p in pin["providers"].values() if p["limits"])
    if not args.quiet:
        print(f"pin_limits: wrote {out} — {len(pin['providers'])} providers, {with_limits} with limits, "
              f"source generated_at={pin['source']['limits_generated_at']}")
        for pid, row in sorted(pin["providers"].items()):
            keys = ", ".join(f"{k}={v['value']}" for k, v in row["limits"].items()) or "none"
            print(f"  {pid:22} {keys}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
