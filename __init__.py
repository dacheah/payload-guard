"""payload-guard — payload-walls pre-flight guard for Hermes.

Compares the request Hermes is about to send against the empirically measured
provider ceilings published in https://github.com/dacheah/payload-walls (pinned into
``limits.pin.json``), and warns before the request is sent. Read-only: it
never rewrites the payload.

Surfaces registered:
  * ``pre_api_request`` hook — always. Measures the real outgoing request, records
    findings, logs a warning on any predicted wall. Read-only: this hook cannot cancel
    or alter a call.
  * ``post_api_request`` hook — calibration: records when a predicted breach was
    accepted anyway, so an over-conservative pin is visible instead of silent.
  * ``/payload-guard`` slash command and ``hermes payload-guard`` CLI.

Config (``config.yaml`` → ``plugins.entries.payload-guard``), all keys optional::

    plugins:
      entries:
        payload-guard:
          enabled: true
          mode: warn            # warn | off ('shrink' was removed in 1.1.0)
          log_calls: false      # info-log every measured call
          token_warn_ratio: 0.9
          pin_path: ""          # override the vendored limits.pin.json
          state_path: ""        # override ~/.hermes/payload-guard/state.json
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:  # loaded as a package by the plugin loader
    from . import guard as g
except ImportError:  # pragma: no cover - loaded as a loose module
    import guard as g  # type: ignore

try:  # the pin builder sits beside us. Never a bare top-level import: the plugin loader
    from . import pin_limits as _pin_limits  # does not put the plugin dir on sys.path, so
except ImportError:  # pragma: no cover - that import silently failed in production and
    import pin_limits as _pin_limits  # type: ignore  # a shadowing module of the same name
    # could otherwise run inside the agent process in its place.

PLUGIN_ID = "payload-guard"
logger = logging.getLogger(f"plugins.{PLUGIN_ID}")

DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": True,
    "mode": "warn",
    "log_calls": False,
    "token_warn_ratio": 0.9,
    "pin_path": "",
    "state_path": "",
}

#: key -> prediction for the in-flight call, so post_api_request can score it.
_PENDING: Dict[str, Dict[str, Any]] = {}
_PENDING_CAP = 64

#: the most recent report from either surface, for /payload-guard and for tests
_LAST: Dict[str, Any] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load_config() -> Dict[str, Any]:
    config = dict(DEFAULT_CONFIG)
    try:
        from hermes_cli.config import load_config as _hermes_config

        try:  # this is a read-only hot path (3 calls per API call): skip the deepcopy
            from hermes_cli.config import load_config_readonly as _readonly
        except ImportError:
            _readonly = None
        raw = (_readonly() if _readonly is not None else _hermes_config()) or {}
        entries = ((raw.get("plugins") or {}).get("entries") or {})
        section = entries.get(PLUGIN_ID) or entries.get("payload_guard") or {}
        if isinstance(section, dict):
            config.update({k: v for k, v in section.items() if v is not None})
    except Exception as exc:  # never break a turn over config
        logger.debug("%s: config load failed: %s", PLUGIN_ID, exc)

    config["mode"] = str(config.get("mode") or "warn").strip().lower()
    if config["mode"] == "shrink":
        # v1.1.0 removed the payload-rewriting middleware: it was never proven against a
        # live rejection, and the brief for this plugin was observe-and-warn. Never silent.
        logger.warning(
            "%s: mode 'shrink' was removed in 1.1.0 (payload rewrites were never proven "
            "against a live rejection; see the shrink-mode branch) — running warn-only",
            PLUGIN_ID,
        )
        config["mode"] = "warn"
    elif config["mode"] not in ("warn", "off"):
        logger.warning("%s: unknown mode %r — falling back to 'warn'", PLUGIN_ID, config["mode"])
        config["mode"] = "warn"
    return config


def _pin(config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    path = g.Path(str(config["pin_path"])) if config.get("pin_path") else None
    return g.load_pin(path)


def _pin_file(config: Dict[str, Any]) -> str:
    """The pin actually in force, so status/check can be seen to agree with the hook."""
    return str(config.get("pin_path") or getattr(g, "PIN_FILE", "?"))


def _pin_display(config: Dict[str, Any]) -> str:
    pin = _pin(config) or {}
    source = pin.get("source") or {}
    return (f"{len(pin.get('providers') or {})} provider rows, pinned "
            f"{str(pin.get('pinned_at'))[:10]} from {source.get('repo') or '?'} "
            f"({_pin_file(config)})")


def _remember(key: str, report: "g.Report") -> None:
    if not key:
        return
    _PENDING[key] = {
        "breach": bool(report.breaches),
        "keys": [f.key for f in report.breaches],
        "provider": report.provider,
        "model": report.model,
        "mode": report.mode,
        "ts": _now(),
    }
    while len(_PENDING) > _PENDING_CAP:
        _PENDING.pop(next(iter(_PENDING)), None)


# --------------------------------------------------------------------------- hooks


def _provider_for_pin(provider: str, pin: Dict[str, Any]) -> str:
    """The name the pin should be resolved under.

    Hermes canonicalises provider names, and the pin may know either form -- but the raw name
    wins when the pin has a row for it, because canonicalisation is not always a synonym:
    Hermes maps bare "openai" to "openrouter" (a different provider, and a different row), so
    following it first would quietly drop the one row whose wall is best measured.
    """
    name = str(provider or "").strip()
    if not name:
        return name
    providers = pin.get("providers") or {}
    aliases = pin.get("aliases") or {}
    candidate = name.lower()
    if candidate in providers or isinstance(aliases.get(candidate), dict):
        return name
    try:
        from hermes_cli.providers import normalize_provider  # type: ignore
        canonical = str(normalize_provider(name) or "").strip().lower()
    except Exception:
        canonical = ""
    if canonical and (canonical in providers or isinstance(aliases.get(canonical), dict)):
        return canonical
    return name


def on_pre_api_request(
    *,
    session_id: str = "",
    model: str = "",
    provider: str = "",
    platform: str = "",
    api_call_count: int = 0,
    api_request_id: str = "",
    retry_count: int = 0,
    request_messages: Any = None,
    conversation_history: Any = None,
    request_char_count: int = 0,
    approx_input_tokens: int = 0,
    system_prompt: Any = None,
    tool_count: int = 0,
    base_url: str = "",
    **_: Any,
) -> None:
    """Measure the request about to be sent; warn and record on any predicted wall."""
    config = _load_config()
    if config["mode"] == "off" or not config.get("enabled", True):
        return
    try:
        pin = _pin(config)
        if not pin:
            return
        # ``request_messages`` are the raw provider-shaped parts; the hook's ``request``
        # payload is sanitised and truncates long strings, so it must not be measured.
        messages = request_messages if isinstance(request_messages, list) and request_messages else conversation_history
        if not isinstance(messages, list):
            return

        key = api_request_id or f"{session_id}:{api_call_count}"
        report = g.preflight(
            messages,
            provider=provider,
            model=model,
            pin=pin,
            mode="warn",
            approx_input_tokens=int(approx_input_tokens or 0),
            token_warn_ratio=float(config.get("token_warn_ratio") or 0.9),
            # Everything the hook can see that shapes the real body. The tool schemas are not
            # passed to this surface, so the figure stays a labelled lower bound.
            resolve_as=_provider_for_pin(provider, pin),
            system_prompt=system_prompt or "",
            tool_count=int(tool_count or 0),
            base_url=base_url,
        )
        report.notes.append(
            f"body estimate {g.human_bytes(report.measure.get('body_bytes'))}; "
            f"hermes counted {int(request_char_count or 0):,} request chars"
        )
        report.notes.append(f"api_call_count={api_call_count} retry_count={retry_count} platform={platform}")

        prior = _PENDING.get(key)
        if prior:
            report.mode = prior.get("mode") or report.mode
        _remember(key, report)
        _LAST.clear()
        _LAST.update({"surface": "pre_api_request", "report": report.as_dict(), "ts": _now()})

        if report.worst == "breach":
            caveat = next((n for n in report.notes
                           if "region mismatch" in n or "not the active model" in n), "")
            for finding in report.breaches:
                logger.warning("%s: predicted wall — %s%s", PLUGIN_ID,
                               g.describe_finding(finding),
                               f" [{caveat}]" if caveat else "")
            g.record(report, config.get("state_path"))
        elif report.worst == "advisory":
            for finding in report.advisories:
                logger.info("%s: advisory — %s", PLUGIN_ID, g.describe_finding(finding))
            if config.get("log_calls"):
                g.record(report, config.get("state_path"))
        elif config.get("log_calls"):
            logger.info("%s: %s", PLUGIN_ID, report.summary())
            g.record(report, config.get("state_path"))
    except Exception as exc:  # never break a turn
        logger.debug("%s: pre_api_request failed: %s", PLUGIN_ID, exc)


def on_post_api_request(
    *,
    session_id: str = "",
    model: str = "",
    provider: str = "",
    api_request_id: str = "",
    api_call_count: int = 0,
    **_: Any,
) -> None:
    """Calibration: a success after a predicted breach means the pin is conservative."""
    key = api_request_id or f"{session_id}:{api_call_count}"
    pending = _PENDING.pop(key, None)
    if not pending or not pending.get("breach"):
        return
    try:
        config = _load_config()
        provider = provider or pending.get("provider") or ""
        model = model or pending.get("model") or ""
        g.record_false_positive(
            {
                "ts": _now(),
                "provider": provider,
                "model": model,
                "keys": pending.get("keys") or [],
                "actions": pending.get("actions") or [],
                "predicted_at": pending.get("ts"),
            },
            config.get("state_path"),
        )
        logger.info(
            "%s: predicted a wall for %s/%s on %s, but the provider accepted the request — "
            "the pin may be conservative or stale",
            PLUGIN_ID,
            provider,
            model,
            ",".join(pending.get("keys") or []) or "?",
        )
    except Exception as exc:
        logger.debug("%s: post_api_request failed: %s", PLUGIN_ID, exc)


def on_api_request_error(
    *,
    session_id: str = "",
    model: str = "",
    provider: str = "",
    api_request_id: str = "",
    api_call_count: int = 0,
    status_code: int = 0,
    retry_count: int = 0,
    error: Any = None,
    **_: Any,
) -> None:
    """The half of the ledger that used to be missing: the provider refused a request.

    ``post_api_request`` only fires once a response was obtained, so a false negative
    (predicted fine, rejected anyway) left no record anywhere — the state file could only
    ever look healthy. This records the outcome for the attempt we predicted on.
    """
    key = api_request_id or f"{session_id}:{api_call_count}"
    pending = _PENDING.pop(key, None)
    try:
        config = _load_config()
        detail = ""
        if isinstance(error, dict):
            detail = g._clean_text(error.get("message") or error.get("type") or "", limit=200)
        elif error:
            detail = g._clean_text(error, limit=200)
        predicted = bool((pending or {}).get("breach"))
        g.record_rejection(
            {
                "outcome": "rejected-as-predicted" if predicted else "missed-wall",
                "provider": provider or (pending or {}).get("provider", ""),
                "model": model or (pending or {}).get("model", ""),
                "status_code": int(status_code or 0),
                "retry_count": int(retry_count or 0),
                "keys": (pending or {}).get("keys") or [],
                "detail": detail,
            },
            config.get("state_path"),
        )
        if predicted:
            logger.info("%s: %s rejected the request (status %s) — as predicted on %s", PLUGIN_ID,
                        provider or "?", int(status_code or 0),
                        ",".join((pending or {}).get("keys") or []) or "?")
        else:
            logger.warning(
                "%s: %s rejected the request (status %s) with no predicted wall%s — a measured "
                "wall may be missing, or the pin is stale", PLUGIN_ID, provider or "?",
                int(status_code or 0), f": {detail}" if detail else "")
    except Exception as exc:  # never break a turn
        logger.debug("%s: api_request_error failed: %s", PLUGIN_ID, exc)


# ------------------------------------------------------------- slash / CLI surfaces


def _status_text(limit: int = 10) -> str:
    # Read the same files the hook writes: a status surface answering from the default path
    # while breaches pile up in a configured one is false assurance, not a cosmetic bug.
    config = _load_config()
    state = g.load_state(config.get("state_path"))
    pin = _pin(config) or {}
    source = pin.get("source") or {}
    limits_known = sum(1 for row in (pin.get("providers") or {}).values() if row.get("limits"))
    lines = [
        f"payload-guard: mode={config['mode']} calls={state.get('calls', 0)} "
        f"breaches={state.get('breaches', 0)} rewrites={state.get('rewrites', 0)} "
        f"accepted-despite-prediction={state.get('false_positives', 0)} "
        f"missed-wall={state.get('missed_walls', 0)} "
        f"rejected-as-predicted={state.get('rejected_as_predicted', 0)}",
        f"pin: {limits_known} of {len(pin.get('providers') or {})} rows carry a numeric limit "
        f"({source.get('repo', '?')}, dataset {str(source.get('limits_generated_at'))[:10]}, "
        f"pinned {str(pin.get('pinned_at'))[:10]}) — {_pin_file(config)}",
        f"state: {g.state_path(config.get('state_path'))}",
        f"pin sha256: {g.pin_digest()[:16] or '—'} "
        f"dataset sha256: {str(source.get('dataset_sha256'))[:16] or '—'} "
        f"builder sha256: {str(source.get('builder_sha256'))[:16] or '—'}",
    ]
    sample: "Dict[str, int]" = {}
    for entry in state.get("last") or []:
        key = str(entry.get("coverage") or "measured")
        sample[key] = sample.get(key, 0) + 1
    if sample:
        lines.append("recent coverage: " + ", ".join(f"{k}={v}" for k, v in sorted(sample.items())))
    last = state.get("last") or []
    if not last:
        lines.append("no findings recorded yet (nothing has breached or been logged)")
    for entry in last[:limit]:
        coverage = str(entry.get("coverage") or "measured")
        stage = "" if coverage == "measured" else f" (checked: {coverage})"   # UNKNOWN is visible here
        rewritten = "[rewritten] " if entry.get("changed") else ""
        lines.append(
            f"  {str(entry.get('ts'))[5:16]} {entry.get('provider')}/{entry.get('model')} "
            f"worst={entry.get('worst')}{stage} {rewritten}{entry.get('detail', '')}"
        )
        for note in (entry.get("notes") or [])[:3]:
            lines.append(f"      note: {note}")
    for entry in (state.get("rejection_last") or [])[:5]:
        lines.append(
            f"  {entry.get('outcome')} {str(entry.get('ts'))[5:16]} "
            f"{entry.get('provider')}/{entry.get('model')} status={entry.get('status_code')}"
            f"{(' — ' + str(entry.get('detail'))[:80]) if entry.get('detail') else ''}"
        )
    for entry in (state.get("false_positive_last") or [])[:5]:
        lines.append(
            f"  accepted-despite-prediction {str(entry.get('ts'))[5:16]} "
            f"{entry.get('provider')}/{entry.get('model')} keys={','.join(entry.get('keys') or [])}"
        )
    return "\n".join(lines)


def _check_report(args: Dict[str, Any]) -> "g.Report":
    """The CLI's check, decided by the same code path as the live hooks (``g.assess``).

    It used to re-implement the comparison, so the two could disagree -- and did: the CLI
    reported a bare verdict with no scope caveat while the hook appended one.
    """
    config = _load_config()
    pin = _pin(config) or {}
    provider = str(args.get("provider") or "")
    model = str(args.get("model") or "")
    images = int(args.get("images") or 0)
    per_image = int(args.get("image_bytes") or 0)
    # The CLI takes decoded image bytes; the pin's caps may be metered in base64 terms,
    # so supply both figures or a basis-aware limit would be checked against the wrong one.
    per_image_encoded = (per_image + 2) // 3 * 4 if per_image else 0
    system_bytes = max(0, int(args.get("system_prompt_bytes") or 0))
    measure = g.Measure(
        messages=int(args.get("messages") or 0),
        images=images,
        image_total_bytes=per_image * images,
        image_max_item_bytes=per_image,
        image_total_encoded_bytes=per_image_encoded * images,
        image_max_item_encoded_bytes=per_image_encoded,
        body_bytes=max(0, int(args.get("body_bytes") or 0)) + system_bytes,
        basis="user-supplied",
        tool_count=max(0, int(args.get("tool_count") or 0)),
    )
    if system_bytes:
        measure.body_scope = "messages+system"
    return g.assess(measure, provider=provider, model=model, mode="check", pin=pin,
                    base_url=str(args.get("base_url") or ""),
                    resolve_as=_provider_for_pin(provider, pin),
                    approx_input_tokens=int(args.get("input_tokens") or 0))


def _check_text(args: Dict[str, Any]) -> str:
    return g.format_report(_check_report(args))


def _parse_flags(argv: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    index = 0
    while index < len(argv):
        token = argv[index]
        if token.startswith("--"):
            out[token[2:].replace("-", "_")] = argv[index + 1] if index + 1 < len(argv) else ""
            index += 2
        else:
            index += 1
    return out


def handle_slash(raw: str = "") -> str:
    """``/payload-guard [status|check|providers|pin]``"""
    argv = (raw or "").split()
    try:
        if argv and argv[0] == "check":
            return _check_text(_parse_flags(argv[1:]))
        if argv and argv[0] == "providers":
            pin = _pin(_load_config()) or {}
            rows = []
            for key, row in sorted((pin.get("providers") or {}).items()):
                limits = ", ".join(
                    f"{name}={spec['value']}"
                    + ("" if str(spec.get("kind")) in ("resolved_cap", "stated_in_error")
                       else f" [{spec.get('kind')}]")
                    for name, spec in sorted((row.get("limits") or {}).items())
                )
                rows.append(f"{key:24} {limits or '(no ceiling known)'}")
            rows.append("\n[hard] = a probe hit that wall; [bracket]/[documented] are advisory. "
                        "A provider with no row here is UNKNOWN, never 'inside the ceiling'.")
            return "\n".join(rows)
        if argv and argv[0] == "pin":
            config = _load_config()
            rc = int(_pin_limits.main([]) or 0)
            if rc:
                return (f"payload-guard: pin NOT regenerated (pin_limits exited {rc}) — still "
                        f"enforcing {_pin_display(config)}")
            return f"payload-guard: pin regenerated — {_pin_display(config)}"
        return _status_text()
    except Exception as exc:
        return f"payload-guard: {exc}"


def setup_cli(parser: Any) -> None:
    """Arguments for ``hermes payload-guard`` (Hermes hands us our own parser)."""
    parser.add_argument(
        "action",
        nargs="?",
        default="status",
        choices=("status", "check", "providers", "pin"),
        help="status (default), check a hypothetical batch, list measured ceilings, or re-pin",
    )
    parser.add_argument("--provider", default="")
    parser.add_argument("--model", default="")
    parser.add_argument("--body-bytes", type=int, default=0)
    parser.add_argument("--messages", type=int, default=0)
    parser.add_argument("--images", type=int, default=0)
    parser.add_argument("--image-bytes", type=int, default=0, help="decoded bytes per image")
    parser.add_argument("--input-tokens", type=int, default=0)
    parser.add_argument("--tool-count", type=int, default=0,
                        help="tool schemas in the request (not visible to the pre-flight hook)")
    parser.add_argument("--system-prompt-bytes", type=int, default=0,
                        help="bytes of system prompt to add to the body figure")
    parser.add_argument("--base-url", default="",
                        help="endpoint the request goes to; a host the row was not measured on "
                             "is reported as UNKNOWN rather than checked")


def handle_cli(args: Any) -> int:
    """CLI entry point: a traceback here is a bad user experience, not a safety net."""
    try:
        return _handle_cli(args)
    except Exception as exc:
        print(f"payload-guard: {exc}")
        return 2


def _handle_cli(args: Any) -> int:
    action = getattr(args, "action", "status") or "status"
    if action == "check":
        # Everything argparse parsed, verbatim: a hand-copied field list is how the CLI and
        # the live hooks came to disagree in the first place.
        values = vars(args) if hasattr(args, "__dict__") else {}
        text = _check_text(dict(values))
        print(text)
        return 1 if "BREACH" in text else 0
    if action == "pin":
        config = _load_config()
        rc = int(_pin_limits.main([]) or 0)
        verdict = "regenerated" if not rc else f"NOT regenerated (rc={rc})"
        print("payload-guard: pin " + verdict + " — " + _pin_display(config))
        return rc
    print(handle_slash("providers" if action == "providers" else "status"))
    return 0


def register(ctx: Any) -> None:
    """Plugin entry point."""
    config = _load_config()
    if not config.get("enabled", True):
        logger.info("%s: disabled by config", PLUGIN_ID)
        return

    ctx.register_hook("pre_api_request", on_pre_api_request)
    ctx.register_hook("post_api_request", on_post_api_request)
    ctx.register_hook("api_request_error", on_api_request_error)
    logger.info("%s: ready in %s mode (pre-flight warnings only)", PLUGIN_ID, config["mode"])

    ctx.register_cli_command(
        "payload-guard",
        "payload-walls pre-flight guard",
        setup_cli,
        handle_cli,
        description="Measure a request against the published provider payload walls.",
    )
    ctx.register_command(
        "payload-guard",
        handle_slash,
        "payload-guard: status, provider ceilings, or check a hypothetical batch",
        "[status|check --provider openai --images 30 --image-bytes 2053887|providers|pin]",
    )

    pin = g.load_pin()
    if pin:
        logger.info(
            "%s: pin loaded — %d providers, dataset %s",
            PLUGIN_ID,
            len(pin.get("providers") or {}),
            (pin.get("source") or {}).get("limits_generated_at", "unknown"),
        )
    else:
        logger.warning("%s: no limits.pin.json — the guard is inert until one exists", PLUGIN_ID)


if __name__ == "__main__":  # manual smoke test: python __init__.py check --provider openai
    print(handle_slash(" ".join(sys.argv[1:])))
