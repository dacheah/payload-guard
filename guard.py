"""payload-walls pre-flight guard — engine.

Measures the request Hermes is about to send (body bytes, image count, per-image and
total image bytes) and compares it against the empirically measured ceilings published
in github.com/dacheah/payload-walls, pinned into ``limits.pin.json``.

Pure module: no Hermes imports at module scope, so it is unit-testable standalone.
The plugin's ``__init__.py`` wires it into ``llm_request`` middleware and the
``pre_api_request`` hook.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from contextlib import contextmanager
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("plugins.payload-guard")

PLUGIN_ID = "payload-guard"
PIN_FILE = Path(__file__).with_name("limits.pin.json")
ALIASES_FILE = Path(__file__).with_name("aliases.json")

#: Limit keys used throughout the pin and the findings.
BODY = "body_bytes"
IMAGE_TOTAL = "image_total_bytes"
ITEM = "item_bytes"
ITEMS = "items"
TOKENS = "input_tokens"

LIMIT_KEYS = (BODY, IMAGE_TOTAL, ITEM, ITEMS, TOKENS)
IMAGE_LIMIT_KEYS = (IMAGE_TOTAL, ITEM, ITEMS)

#: kinds that describe a hard, resolved ceiling
HARD_KINDS = ("resolved_cap", "stated_in_error")

_DATA_URI_RE = re.compile(r"^data:(?P<mime>[^;,]*)?(?:;charset=[^;,]*)?(?P<b64>;base64)?,", re.I)


# --------------------------------------------------------------------------------------
# measurement
# --------------------------------------------------------------------------------------


@dataclass
class Measure:
    """What the outgoing request actually contains, as far as we can see it."""

    messages: int = 0
    images: int = 0
    image_total_bytes: int = 0
    image_max_item_bytes: int = 0
    image_total_encoded_bytes: int = 0
    image_max_item_encoded_bytes: int = 0
    unmetered_images: int = 0
    body_bytes: int = 0
    text_chars: int = 0
    nonascii_chars: int = 0
    basis: str = "estimate"
    #: True when the walk hit its node budget or a repeated container: body_bytes is then a
    #: lower bound, and no verdict may claim the payload is inside a body ceiling.
    body_incomplete: bool = False
    #: What the body figure covers: "messages" (the pre-flight hook sees only the messages),
    #: "messages+system", or "whole-request" (the middleware surface, where the real request
    #: dict is available). The pin's body ceilings are whole-request numbers, so anything
    #: short of "whole-request" is a LOWER bound and every report says so.
    body_scope: str = "messages"
    #: Tool schemas the surface cannot see, when Hermes tells us how many there are.
    tool_count: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "messages": self.messages,
            "images": self.images,
            "image_total_bytes": self.image_total_bytes,
            "image_max_item_bytes": self.image_max_item_bytes,
            "image_total_encoded_bytes": self.image_total_encoded_bytes,
            "image_max_item_encoded_bytes": self.image_max_item_encoded_bytes,
            "unmetered_images": self.unmetered_images,
            "body_bytes": self.body_bytes,
            "text_chars": self.text_chars,
            "nonascii_chars": self.nonascii_chars,
            "basis": self.basis,
            "body_incomplete": self.body_incomplete,
            "body_scope": self.body_scope,
            "tool_count": self.tool_count,
        }


#: Hard bound on nodes walked per measurement. A payload whose object graph is not a tree
#: (shared or cyclic containers) must not be able to spin the hook thread; hitting the bound
#: makes the body figure a lower bound, which the report says out loud.
NODE_BUDGET = 2_000_000
#: Only this many characters of a "data:" string are pattern-matched; the rest is payload.
DATA_URI_HEAD = 512
_SUPPORTED_PIN_VERSION = 1
_MAX_INT = 2 ** 62

#: Load state of the pin: ok | missing | unreadable | invalid. Set by load_pin().
PIN_STATE: Dict[str, str] = {"status": "ok", "detail": "", "sha256": "", "path": ""}


def _finite_int(value: Any) -> Optional[int]:
    """``int(value)`` when that is finite, else None. Never raises, never returns inf."""
    if isinstance(value, bool):
        return int(value)
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if number > _MAX_INT or number < -_MAX_INT:
        return None
    return number


def _finite_float(value: Any, default: float = 1.0) -> float:
    """``float(value)`` when that is finite, else ``default``. Never raises."""
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if number != number or number in (float("inf"), float("-inf")):
        return default
    return number


def _clean_text(value: Any, limit: int = 800) -> str:
    """Sanitise third-party (dataset) text before it reaches a log line or the terminal.

    Pin notes are someone else's prose: they must not be able to forge a log line with a
    newline, drive the terminal with escape sequences, or pad the state file.
    """
    text = str(value or "")
    if not text:
        return ""
    out = []
    for char in text:
        code = ord(char)
        if char in "\n\r\t":
            out.append(" ")
        elif code < 32 or 127 <= code <= 159:
            continue
        else:
            out.append(char)
    cleaned = " ".join("".join(out).split())
    return cleaned[:limit] + ("…" if len(cleaned) > limit else "")


def _str_size(value: str) -> Tuple[int, int, int]:
    """Return (json-encoded size, chars, non-ascii chars) for a string under ensure_ascii.

    Non-ASCII is measured with C-speed byte ops rather than a per-character Python loop:
    each non-ASCII char is counted at the 6-byte width of its ``\\uXXXX`` escape. That is a
    worst case (a body sent as raw UTF-8 bytes is smaller), so it over-estimates rather than
    under-estimates -- and the reported non-ascii count is what tells you it did.
    """
    length = len(value)
    extra = value.count('"') + value.count("\\")
    if value.isascii():
        return 2 + length + extra, length, 0
    ascii_part = value.encode("ascii", "ignore")
    nonascii = length - len(ascii_part)
    return 2 + len(ascii_part) + 6 * nonascii + extra, length, nonascii


def _jsonable(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        return str(value)


def estimate_body_bytes(value: Any, *, node_budget: int = NODE_BUDGET,
                        incomplete: Optional[List[bool]] = None) -> Tuple[int, int, int]:
    """Estimate ``len(json.dumps(value, separators=(",", ":")))`` without serialising.

    Returns ``(bytes, text_chars, nonascii_chars)``. Exact for the base64/ASCII payloads
    that matter here; non-ASCII is counted at its escaped width (see :func:`_str_size`).

    Bounded twice so it cannot spin on the hot path: each container is walked at most once
    (a shared or cyclic subgraph would otherwise be walked forever, where ``json.dumps``
    raises immediately), and the walk stops after ``node_budget`` nodes. Hitting either sets
    ``incomplete[0]``, and the caller must then report the figure as a lower bound.
    """
    total = 0
    chars = 0
    nonascii = 0
    # Only the current branch is tracked: a container shared between siblings really is
    # serialised once per occurrence and must be counted each time, while revisiting a node
    # on its own branch is a cycle (``json.dumps`` raises on it) and is skipped.
    path: set = set()
    nodes = int(node_budget)
    stack: List[Tuple[Any, bool]] = [(value, False)]
    while stack:
        if nodes <= 0:
            if incomplete is not None:
                incomplete[0] = True
            break
        nodes -= 1
        node, leaving = stack.pop()
        if leaving:
            path.discard(id(node))
            continue
        ty = type(node)
        if node is None:
            total += 4
        elif ty is bool:
            total += 4 if node else 5
        elif ty in (int, float):
            total += len(repr(node))
        elif ty is str:
            size, n_chars, n_nonascii = _str_size(node)
            total += size
            chars += n_chars
            nonascii += n_nonascii
        elif ty is dict:
            if id(node) in path:
                if incomplete is not None:
                    incomplete[0] = True
                continue
            path.add(id(node))
            total += 2 + max(0, len(node) - 1)
            stack.append((node, True))
            for key, val in node.items():
                ksize, kchars, knonascii = _str_size(str(key))
                total += ksize + 1  # key plus its colon; the commas are counted above
                chars += kchars
                nonascii += knonascii
                stack.append((val, False))
        elif ty in (list, tuple, set, frozenset):
            if id(node) in path:
                if incomplete is not None:
                    incomplete[0] = True
                continue
            path.add(id(node))
            total += 2 + max(0, len(node) - 1)
            stack.append((node, True))
            stack.extend((child, False) for child in node)
        else:
            size, n_chars, n_nonascii = _str_size(_jsonable(node))
            total += size
            chars += n_chars
            nonascii += n_nonascii
    return total, chars, nonascii


#: Request keys the host hands to the HTTP client rather than serialising into the body.
TRANSPORT_KEYS = frozenset({"timeout", "http_client", "httpx_client", "request_timeout"})
#: The only scope in which a body figure is a whole-body measurement.
BODY_SCOPE_WHOLE = "whole-request"
#: How close to a body ceiling a partial-scope figure may get before the report warns that
#: the real body (tool schemas included) could cross it.
BODY_SCOPE_MARGIN = 0.75


def estimate_request_body(request: Any) -> Optional[int]:
    """Whole-request body bytes, or None when there is no request mapping to measure.

    The pin's body ceilings describe the whole request, tool schemas included, so a figure
    taken from ``messages`` alone understates it. Only the middleware surface has the dict
    Hermes is about to serialise, so only there is a body figure a whole-body figure.
    """
    if not isinstance(request, dict):
        return None
    payload = {k: v for k, v in request.items() if k not in TRANSPORT_KEYS}
    measured = estimate_body_bytes(payload)
    return measured[0] if isinstance(measured, tuple) else measured


def _host_of(value: Any) -> str:
    """Hostname out of a base URL or a pinned host value (which may carry a path)."""
    text = str(value or "").strip().lower()
    if not text:
        return ""
    text = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", text)
    text = text.split("/", 1)[0].split("?", 1)[0]
    text = text.rsplit("@", 1)[-1]
    if text.startswith("["):
        text = text.split("]", 1)[0] + "]"
    else:
        text = text.split(":", 1)[0]
    return text[4:] if text.startswith("www.") else text


def _same_host(a: str, b: str) -> bool:
    """True when the two hostnames are the same endpoint (or one cannot be read)."""
    if not a or not b:
        return True
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _data_uri_sizes(url: Any) -> Optional[Tuple[int, int]]:
    """(decoded bytes, base64 chars) of a data URI, or None if it is not one."""
    if not isinstance(url, str) or not url.startswith("data:"):
        return None
    # Match a bounded head only: a huge "data:"-prefixed string that is not a data URI must
    # not cost a full backtracking scan on the hot path. ``match`` is anchored at 0, so the
    # offsets stay valid against the whole string.
    match = _DATA_URI_RE.match(url[:DATA_URI_HEAD])
    if not match or not match.group("b64"):
        _, _, payload = url.partition(",")
        raw = len(payload.encode("utf-8", "ignore")) if payload else 0
        return raw, raw
    payload = url[match.end():]
    padding = len(payload) - len(payload.rstrip("="))
    return max(0, (len(payload) * 3) // 4 - padding), len(payload)


def _part_image(url_or_source: Any) -> Tuple[bool, Optional[int], Optional[int]]:
    """Classify one content part's image-ish value → (is_image, decoded, encoded)."""
    if url_or_source is None:
        return False, None, None
    if isinstance(url_or_source, str):
        sizes = _data_uri_sizes(url_or_source)
        if sizes is not None:
            return True, sizes[0], sizes[1]
        if url_or_source.startswith(("http://", "https://")):
            return True, None, None
        return False, None, None
    if isinstance(url_or_source, dict):
        # Anthropic native: {"type": "base64", "media_type": ..., "data": "<b64>"}
        if "data" in url_or_source and str(url_or_source.get("type", "")) in {"base64", ""}:
            data = url_or_source.get("data")
            if isinstance(data, str):
                padding = len(data) - len(data.rstrip("="))
                return True, max(0, (len(data) * 3) // 4 - padding), len(data)
        for key in ("url", "image_url", "uri", "b64_json", "data"):
            if key in url_or_source:
                found, decoded, encoded = _part_image(url_or_source[key])
                if found:
                    return True, decoded, encoded
        return False, None, None
    return False, None, None


def measure_messages(messages: Any) -> Measure:
    """Walk provider-shaped messages and measure images + body size."""
    result = Measure()
    if not isinstance(messages, list):
        messages = []
    result.messages = len(messages)

    def scan_part(part: Any, depth: int = 0) -> None:
        if isinstance(part, str) or not isinstance(part, dict) or depth > 12:
            return
        ptype = str(part.get("type") or "")
        if ptype in {"image_url", "input_image"}:
            _account(*_part_image(part.get("image_url")))
            return
        if ptype == "image" or ("source" in part and ptype.startswith("image")):
            _account(*_part_image(part.get("source")))
            return
        if "inline_data" in part or "inlineData" in part:
            _account(*_part_image(part.get("inline_data") or part.get("inlineData")))
            return
        # Images are not always at the top level: on the anthropic_messages wire a tool
        # result carries its images inside tool_result.content, and Gemini nests them in
        # functionResponse.parts. Those are exactly the places a long tool loop accumulates
        # them, so a walk that stops at the top level reports "OK" for a payload the
        # provider will reject.
        nested = False
        for key in ("content", "parts", "functionResponse", "function_response"):
            inner = part.get(key)
            if isinstance(inner, (list, dict)):
                nested = True
                if isinstance(inner, list):
                    for child in inner:
                        scan_part(child, depth + 1)
                else:
                    scan_part(inner, depth + 1)
        if nested:
            return
        # Be defensive: an unknown part that mentions an image is an unmeasured image,
        # never a silent zero.
        for key in ("image_url", "image", "image_base64", "b64_json"):
            if key in part:
                found, decoded, encoded = _part_image(part[key])
                if found:
                    _account(found, decoded, encoded)
                else:
                    result.images += 1
                    result.unmetered_images += 1
                return

    def _account(found: bool, decoded: Optional[int], encoded: Optional[int] = None) -> None:
        if not found:
            return
        result.images += 1
        if decoded is None:
            result.unmetered_images += 1
            return
        result.image_total_bytes += decoded
        result.image_total_encoded_bytes += encoded if encoded is not None else decoded * 4 // 3
        if decoded > result.image_max_item_bytes:
            result.image_max_item_bytes = decoded
        if (encoded or 0) > result.image_max_item_encoded_bytes:
            result.image_max_item_encoded_bytes = encoded or 0

    for message in messages:
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, list):
            for part in content:
                scan_part(part)
        elif isinstance(content, dict):
            scan_part(content)
        if isinstance(message.get("images"), list):
            for item in message["images"]:
                scan_part(item if isinstance(item, dict) else {"type": "image_url", "image_url": item})

    incomplete = [False]
    result.body_bytes, result.text_chars, result.nonascii_chars = estimate_body_bytes(
        messages, incomplete=incomplete
    )
    result.body_incomplete = bool(incomplete[0])
    return result


# --------------------------------------------------------------------------------------
# pin loading + provider resolution
# --------------------------------------------------------------------------------------


_PIN_CACHE: Dict[str, Any] = {"path": None, "mtime": None, "data": None}


def _pin_problem(data: Any) -> str:
    """Why this pin cannot be trusted as a dataset, or "" when it is usable.

    A pin that parses but is not the expected shape is the dangerous case: without this the
    guard enforces nothing while still printing ceilings to the user.
    """
    if not isinstance(data, dict):
        return "top level is not an object"
    version = data.get("pin_version")
    if version is not None:
        parsed = _finite_int(version)
        if parsed is None or parsed > _SUPPORTED_PIN_VERSION:
            return f"pin_version {version!r} is not supported (this build reads {_SUPPORTED_PIN_VERSION})"
    providers = data.get("providers")
    if not isinstance(providers, dict):
        return "providers is not an object"
    aliases = data.get("aliases")
    if aliases is not None and not isinstance(aliases, dict):
        return "aliases is not an object"
    for pid, row in providers.items():
        if not isinstance(row, dict):
            return f"provider {pid!r} is not an object"
        limits = row.get("limits")
        if limits is not None and not isinstance(limits, dict):
            return f"provider {pid!r} limits is not an object"
        for key, spec in (limits or {}).items():
            if not isinstance(spec, dict):
                return f"{pid}.limits.{key} is not an object"
            if _finite_int(spec.get("value")) is None:
                return f"{pid}.limits.{key}.value is not a finite number"
    return ""


def load_pin(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load (and memoise by mtime) the pinned limits file.

    Returns ``{"providers": {}, "aliases": {}}`` when the pin is missing, unreadable or not
    the expected shape -- and records why in :data:`PIN_STATE`, so no caller can mistake an
    unusable pin for "nothing to worry about". Logged once per file version, not per call.
    """
    target = Path(path) if path else PIN_FILE
    try:
        mtime = target.stat().st_mtime
    except OSError as exc:
        if PIN_STATE["status"] != "missing":
            logger.warning("payload-guard: pin not readable (%s): %s", target, exc)
        PIN_STATE.update({"status": "missing", "detail": f"pin not readable: {exc}"})
        return {"providers": {}, "aliases": {}}
    if _PIN_CACHE["path"] == str(target) and _PIN_CACHE["mtime"] == mtime:
        return _PIN_CACHE["data"]
    try:
        raw = target.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        logger.warning("payload-guard: pin unreadable (%s): %s", target, exc)
        PIN_STATE.update({"status": "unreadable", "detail": _clean_text(exc, 200)})
        return {"providers": {}, "aliases": {}}
    problem = _pin_problem(data)
    if problem:
        logger.warning("payload-guard: pin rejected as unusable (%s): %s", target, problem)
        PIN_STATE.update({"status": "invalid", "detail": problem})
        return {"providers": {}, "aliases": {}}
    # The digest is the receipt a reader can check: sha256 of the pin exactly as loaded, plus
    # (inside the pin) the dataset it was built from. Provenance is still self-asserted --
    # there is no signature -- but it is now checkable rather than merely claimed.
    PIN_STATE.update({"status": "ok", "detail": "",
                      "sha256": hashlib.sha256(raw).hexdigest(), "path": str(target)})
    _PIN_CACHE.update({"path": str(target), "mtime": mtime, "data": data})
    return data


def pin_digest() -> str:
    """sha256 of the pin as loaded ("" when it was never loaded or could not be read)."""
    return str(PIN_STATE.get("sha256") or "")


def pin_path() -> str:
    """The pin file the guard actually loaded."""
    try:
        return str(PIN_STATE.get("path") or PIN_FILE)
    except Exception:
        return ""


@dataclass
class Resolution:
    hermes_provider: str
    key: Optional[str] = None
    row: Optional[Dict[str, Any]] = None
    match: str = "none"  # none | provider | provider+model
    region_mismatch: bool = False
    note: str = ""
    #: The host the matched row was measured on, and whether the request went elsewhere.
    host: str = ""
    host_mismatch: bool = False

    @property
    def found(self) -> bool:
        return self.row is not None


def _norm_model(value: Any) -> str:
    return str(value or "").strip().lower()


def resolve(pin: Dict[str, Any], provider: str, model: str = "",
            base_url: str = "") -> Resolution:
    """Map a Hermes provider/model onto a measured pin row.

    ``base_url``, when the caller has it, is checked against the host the row was measured on:
    a ceiling measured on api.openai.com says nothing about a gateway or a regional endpoint.
    """
    providers = pin.get("providers") or {}
    aliases = pin.get("aliases") or {}
    name = str(provider or "").strip().lower()
    if not name:
        return Resolution(hermes_provider=name, note="no provider reported")

    entry = aliases.get(name) or {}
    key = entry.get("key") if isinstance(entry, dict) else None
    key = key or name
    row = providers.get(key)
    if not isinstance(row, dict):
        # An alias pointing at a key this pin does not carry must not hide a row that exists
        # under the name as given: Hermes canonicalises bare "openai" to "openrouter", and
        # following that blindly drops the openai row -- a false negative on the provider whose
        # wall is the best measured of the lot.
        if key != name and isinstance(providers.get(name), dict):
            return Resolution(hermes_provider=name, key=name, row=providers[name],
                              match="provider",
                              note=f"alias '{name}' points at '{key}', which this pin does not "
                                   f"carry; used the row under '{name}'")
        return Resolution(hermes_provider=name, key=key, note=f"no measured row for '{key}'")

    resolution = Resolution(
        hermes_provider=name,
        key=key,
        row=row,
        match="provider",
        region_mismatch=bool(entry.get("region_mismatch")) if isinstance(entry, dict) else False,
        note=_clean_text(entry.get("note", "")) if isinstance(entry, dict) else "",
    )
    measured_on = _norm_model(row.get("measured_on"))
    active = _norm_model(model)
    # Exact equality only. A prefix relation ("gemini-3.5-flash" vs the measured
    # "gemini-3.5-flash-lite", or a bare "gemini") is NOT the same model, and treating it as
    # one would attach a model-scoped ceiling to the active model without the caveat that
    # goes with the mismatch.
    if measured_on and active and active == measured_on:
        resolution.match = "provider+model"

    row_host = _host_of(row.get("host"))
    wanted_host = _host_of(base_url)
    resolution.host = row_host
    if row_host and wanted_host and not _same_host(row_host, wanted_host):
        resolution.host_mismatch = True
        caveat = (f"the request went to {wanted_host}, but this row was measured on {row_host} "
                  "-- the ceiling may not apply to that endpoint")
        resolution.note = (resolution.note + " | " if resolution.note else "") + caveat
    return resolution


# --------------------------------------------------------------------------------------
# evaluation
# --------------------------------------------------------------------------------------


@dataclass
class Finding:
    key: str
    value: int
    limit: Optional[int]
    severity: str  # breach | beyond_observed | ok
    kind: str = ""
    scope: str = ""
    note: str = ""
    basis: str = ""
    factor: float = 1.0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "limit": self.limit,
            "severity": self.severity,
            "kind": self.kind,
            "scope": self.scope,
            "note": self.note,
            "basis": self.basis,
            "factor": self.factor,
        }


def limit_value(measure: Measure, key: str, spec: Dict[str, Any]) -> int:
    """The number to compare against ``spec``'s cap, in the basis the vendor meters.

    ``basis: encoded`` compares base64-encoded image bytes (what the vendor's own
    counter saw in our probes), ``decoded`` compares the raw image bytes.
    ``metered_factor`` scales our figure onto the vendor's own count where the two were
    measured to differ (`openai`, where the vendor's number ran ~2.6% above ours).
    """
    basis = str(spec.get("basis") or "decoded")
    try:
        factor = float(spec.get("metered_factor") or 1.0)
    except (TypeError, ValueError):
        factor = 1.0
    if key == BODY:
        raw = measure.body_bytes
    elif key == ITEMS:
        raw = measure.images
    elif key == IMAGE_TOTAL:
        raw = measure.image_total_encoded_bytes if basis == "encoded" else measure.image_total_bytes
    elif key == ITEM:
        raw = measure.image_max_item_encoded_bytes if basis == "encoded" else measure.image_max_item_bytes
    else:
        raw = 0
    return int(raw * factor)


def evaluate(measure: Measure, resolution: Resolution, *, observed: bool = True) -> List[Finding]:
    """Compare a measurement to a pin row. Returns every finding, worst-first."""
    row = resolution.row or {}
    limits = row.get("limits") or {}
    observed_max = row.get("observed_max") or {}
    findings: List[Finding] = []

    measured_values = {
        BODY: measure.body_bytes,
        IMAGE_TOTAL: measure.image_total_bytes,
        ITEM: measure.image_max_item_bytes,
        ITEMS: measure.images,
    }

    for key, limit in limits.items():
        if key not in measured_values:
            continue
        spec = limit if isinstance(limit, dict) else {"value": limit}
        cap = _finite_int(spec.get("value"))
        if cap is None:
            # An unreadable cap drops that one key, never the whole measurement, and says so
            # rather than continuing as if the key were absent.
            findings.append(Finding(key, int(measured_values.get(key, 0) or 0), None, "beyond_observed",
                                    "unreadable", "provider",
                                    "the pinned value for this key is not a finite number — "
                                    "no ceiling was applied"))
            continue
        value = limit_value(measure, key, spec)
        basis = str(spec.get("basis") or "decoded")
        factor = _finite_float(spec.get("metered_factor"), 1.0)
        kind = str(spec.get("kind") or "")
        scope = str(spec.get("scope") or "provider")
        note = _clean_text(spec.get("note") or "")
        if key == BODY and measure.body_scope != BODY_SCOPE_WHOLE:
            note = (note + " " if note else "") + (
                f"body figure covers {measure.body_scope} only, so it is a lower bound on what "
                "the provider receives"
            )
        if value > cap:
            severity = "breach" if kind in HARD_KINDS else "beyond_observed"
            if scope == "model" and resolution.match != "provider+model":
                severity = "beyond_observed"
                note = (note + " " if note else "") + (
                    f"measured on {row.get('measured_on')}, not the active model"
                )
            findings.append(Finding(key, value, cap, severity, kind, scope, note, basis, factor))
        else:
            findings.append(Finding(key, value, cap, "ok", kind, scope, note, basis, factor))

    if observed and not any(f.kind == "capability" for f in findings if f.severity != "ok"):
        # Only the body gets an "unknown territory" advisory. Image counts come in probe
        # ladders, so the largest count we happened to accept is not a ceiling and using
        # it as one produces noise (17 images is not "beyond" a host where 100 passed).
        accepted_body = observed_max.get("body_bytes")
        # Not on a capability-only row (upstage: images are refused outright, so the 109 B
        # its 3-row text probe accepted is an artefact, not a ceiling) and not when the
        # probes only ever sent a trivial body.
        capability_only = str((limits.get(ITEMS) or {}).get("kind") or "") == "capability"
        if (not capability_only and isinstance(accepted_body, int) and accepted_body >= 64 * 1024
                and measure.body_bytes > accepted_body):
            # Only where a body wall was actually probed, and only for a material
            # exceedance: on a capability-only row (upstage: 109 B from a 3-row text probe)
            # this used to fire on every ordinary request and read as a ceiling.
            findings.append(
                Finding(BODY, measure.body_bytes, accepted_body, "beyond_observed", "accepted_max", "provider",
                        f"largest accepted body this row observed: {_human(accepted_body)} — "
                        "not a ceiling, and no probe on record took this host larger")
            )

    order = {"breach": 0, "beyond_observed": 1, "ok": 2}
    findings.sort(key=lambda f: (order.get(f.severity, 3), -(f.limit or 0)))
    return findings


def evaluate_tokens(pin_row: Optional[Dict[str, Any]], approx_input_tokens: int,
                    resolution: Optional[Resolution] = None, *, ratio: float = 0.9) -> Optional[Finding]:
    """Token-budget check for the hook path (Hermes hands us its own token estimate)."""
    limits = (pin_row or {}).get("limits") or {}
    spec = limits.get(TOKENS)
    if not isinstance(spec, dict) or not approx_input_tokens:
        return None
    cap = _finite_int(spec.get("value"))
    if cap is None:
        return None
    if resolution is not None and resolution.match != "provider+model":
        return Finding(TOKENS, approx_input_tokens, cap, "beyond_observed", "resolve", "model",
                       f"token budget measured on {(pin_row or {}).get('measured_on')}, not the active model")
    if approx_input_tokens > cap:
        return Finding(TOKENS, approx_input_tokens, cap, "breach", str(spec.get("kind") or ""), "model",
                       "input token budget")
    if approx_input_tokens >= cap * ratio:
        return Finding(TOKENS, approx_input_tokens, cap, "beyond_observed", "ratio", "model",
                       f"within {int(ratio * 100)}% of the measured input-token budget")
    return None


def breaches(findings: Iterable[Finding]) -> List[Finding]:
    return [f for f in findings if f.severity == "breach"]


# --------------------------------------------------------------------------------------
# actions (only ever taken in shrink mode)
# --------------------------------------------------------------------------------------


def plan_actions(measure: Measure, findings: List[Finding]) -> List[Dict[str, Any]]:
    """Decide the minimal payload surgery that would clear a predicted breach."""
    actions: List[Dict[str, Any]] = []
    hard = breaches(findings)
    if not hard:
        return actions
    keys = {f.key for f in hard}

    if ITEMS in keys:
        target = _finite_int(next((f.limit for f in hard if f.key == ITEMS), None))
        if target is not None:
            actions.append({"action": "drop_oldest_images", "target_images": max(0, target),
                            "reason": f"{measure.images} images > limit {target}"})
    if keys & {IMAGE_TOTAL, ITEM, BODY}:
        actions.append({"action": "shrink_images", "reason": "image bytes over a measured wall"})
    return actions


def drop_oldest_images(messages: List[Any], target_images: int, *, protect_last: int = 1,
                       placeholder: str = "[older image removed by payload-guard to fit the provider limit]") -> int:
    """Remove expendable image parts oldest-first until at/under ``target_images``.

    Returns the number of parts removed. Two things are never touched: the last
    ``protect_last`` messages (the live turn) and any ``role: user`` message, because a
    user's upload is theirs to keep -- the model must not end up answering about photos that
    were silently deleted. Removal stops as soon as the count fits, so a one-image overshoot
    costs one image rather than a whole message's worth.
    """
    if not isinstance(messages, list):
        return 0
    if not isinstance(target_images, int):
        target_images = _finite_int(target_images)
        if target_images is None:
            return 0
    removed = 0
    remaining = content_count(messages)
    live_from = max(0, len(messages) - max(0, protect_last))
    for index in range(live_from):
        if remaining <= target_images:
            break
        message = messages[index]
        if not isinstance(message, dict):
            continue
        # A user upload is never evicted: Hermes' own policy reserves the images the user
        # attached, and a guard that deletes them makes the model answer about photos it can
        # no longer see. Only older tool-result carriers are expendable.
        if str(message.get("role") or "").strip().lower() == "user":
            continue
        content = message.get("content")
        if not isinstance(content, list):
            continue
        kept = []
        for part in content:
            if remaining > target_images and removed_here(part):
                removed += 1
                remaining -= 1
                continue
            kept.append(part)
        if len(kept) != len(content):
            if not kept:
                kept = [{"type": "text", "text": placeholder}]
            message["content"] = kept
    return removed


def removed_here(part: Any) -> bool:
    if not isinstance(part, dict):
        return False
    ptype = str(part.get("type") or "")
    if ptype in {"image_url", "input_image", "image"}:
        return True
    return any(key in part for key in ("inline_data", "inlineData"))


def content_count(messages: List[Any]) -> int:
    count = 0
    for message in messages:
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, list):
            count += sum(1 for part in content if removed_here(part))
    return count


def shrink_images(messages: List[Any], *, max_dimension: int = 8000) -> bool:
    """Re-encode oversized image parts via Hermes' own recovery helper (in place)."""
    try:
        from agent.conversation_compression import try_shrink_image_parts_in_messages
    except Exception as exc:  # running outside Hermes (unit tests) or helper moved
        logger.debug("payload-guard: shrink helper unavailable (%s)", exc)
        return False
    try:
        return bool(try_shrink_image_parts_in_messages(messages, max_dimension=max_dimension))
    except Exception as exc:
        logger.warning("payload-guard: shrink failed: %s", exc)
        return False


def apply_actions(messages: List[Any], actions: List[Dict[str, Any]], measure: Measure, *,
                  max_dimension: int = 8000) -> Tuple[List[Dict[str, Any]], Measure]:
    """Run the planned actions on ``messages`` in place; return (taken, fresh measure)."""
    taken: List[Dict[str, Any]] = []
    current = measure
    for action in actions:
        name = action.get("action")
        if name == "drop_oldest_images":
            target = int(action.get("target_images") or 0)
            removed = drop_oldest_images(messages, target)
            if removed:
                taken.append({"action": name, "removed_images": removed, "target_images": target})
        elif name == "shrink_images":
            if shrink_images(messages, max_dimension=max_dimension):
                taken.append({"action": name, "max_dimension": max_dimension})
    if taken:
        current = measure_messages(messages)
    return taken, current


# --------------------------------------------------------------------------------------
# one-call pre-flight
# --------------------------------------------------------------------------------------


@dataclass
class Report:
    provider: str = ""
    model: str = ""
    pin_key: Optional[str] = None
    match: str = "none"
    mode: str = "warn"
    measure: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    actions: List[Dict[str, Any]] = field(default_factory=list)
    changed: bool = False
    notes: List[str] = field(default_factory=list)
    #: measured (a row with limits was found) | no-row | no-limits | pin-invalid | partial.
    #: Anything other than ``measured`` means the request was NOT checked against a ceiling,
    #: and ``worst`` says so instead of reporting ok.
    coverage: str = "measured"

    @property
    def worst(self) -> str:
        """``breach`` | ``advisory`` | ``ok`` | ``unknown`` (nothing was actually checked)."""
        severity = {f.severity for f in self.findings}
        if "breach" in severity:
            return "breach"
        measured = self.measure or {}
        incomplete = (int(measured.get("unmetered_images") or 0) > 0
                      or bool(measured.get("body_incomplete")))
        if self.coverage != "measured" or incomplete:
            return "unknown"
        if "beyond_observed" in severity:
            return "advisory"
        return "ok"

    @property
    def outcome(self) -> str:
        """One phrase for every surface: the verdict, and why there is not one."""
        if self.worst == "breach":
            return "BREACH — a measured ceiling was exceeded"
        if self.worst == "advisory":
            return "advisory — inside every measured ceiling, with notes"
        if self.worst == "ok":
            return "OK — inside every measured ceiling for this provider"
        if self.coverage == "no-row":
            return f"UNKNOWN — no measured row for {self.pin_key or self.provider or '?'}; not checked"
        if self.coverage == "no-limits":
            return (f"UNKNOWN — a row exists for {self.pin_key} but no probe on record bound this "
                    "host; not checked")
        if self.coverage == "pin-invalid":
            return "UNKNOWN — the pinned dataset is unusable; not checked"
        if self.coverage == "host-mismatch":
            return ("UNKNOWN — the request did not go to the host this row was measured on; "
                    "not checked")
        if int((self.measure or {}).get("unmetered_images") or 0) > 0:
            count = int(self.measure["unmetered_images"])
            return (f"UNKNOWN — {count} image(s) could not be sized (not a data URI), so this "
                    "payload was not fully checked")
        if self.coverage == "partial" or (self.measure or {}).get("body_incomplete"):
            return "UNKNOWN — the payload could not be measured in full; not checked"
        return f"UNKNOWN ({self.coverage})"

    @property
    def breaches(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == "breach"]

    @property
    def advisories(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == "beyond_observed"]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "pin_key": self.pin_key,
            "match": self.match,
            "mode": self.mode,
            "worst": self.worst,
            "measure": self.measure,
            "findings": [f.as_dict() for f in self.findings],
            "actions": self.actions,
            "changed": self.changed,
            "notes": self.notes,
            "coverage": self.coverage,
        }

    def summary(self) -> str:
        measure = self.measure or {}
        parts = [
            f"{self.provider or '?'}/{self.model or '?'}",
            f"images={measure.get('images', 0)}"
            f" image_bytes={_human(measure.get('image_total_bytes', 0))}"
            f" body={_human(measure.get('body_bytes', 0))}"
            + ("" if measure.get("body_scope") in (None, "", BODY_SCOPE_WHOLE)
               else f" ({measure.get('body_scope')})"),
        ]
        if self.findings:
            moved = [f for f in self.findings if f.severity != "ok"]
            detail = "; ".join(describe_finding(f) for f in moved) or "all limits ok"
            parts.append(f"{self.worst}: {detail}")
        elif self.coverage == "measured":
            parts.append("no limit known for this provider")
        else:
            parts.append(f"not checked ({self.coverage})")
        if self.actions:
            parts.append("actions=" + ",".join(str(a.get("action")) for a in self.actions))
        return " | ".join(parts)


def assess(measure: "Measure", *, provider: str = "", model: str = "", mode: str = "warn",
           pin: Optional[Dict[str, Any]] = None, base_url: str = "", resolve_as: str = "",
           approx_input_tokens: int = 0, token_warn_ratio: float = 0.9) -> Report:
    """Evaluate a measurement against the pin.

    Shared by :func:`preflight` (the live hooks) and the CLI, so the two cannot drift: one set
    of coverage rules, caveats and findings decides both. The measure carries its own scope
    (``body_scope``) because this function cannot know what the caller was able to see.
    """
    pin = pin if pin is not None else load_pin()
    resolution = resolve(pin, resolve_as or provider, model, base_url=base_url)
    report = Report(provider=provider, model=model, pin_key=resolution.key, match=resolution.match,
                    mode=mode, measure=measure.as_dict())
    if resolution.region_mismatch:
        report.notes.append("region mismatch: this row was measured on the international host "
                            "and the name in use points at a different host")
    if resolution.note:
        report.notes.append(resolution.note)
    if not pin.get("providers"):
        # No usable pin at all: say so loudly rather than reporting ok for everything.
        report.coverage = "pin-invalid" if PIN_STATE.get("status") in {"invalid", "unreadable"} else "no-row"
        report.notes.append(f"pinned dataset unusable ({PIN_STATE.get('status')}): "
                            f"{PIN_STATE.get('detail') or 'no providers loaded'}")
        return report
    if measure.body_incomplete:
        report.coverage = "partial"
        report.notes.append(
            "the body could not be measured in full (repeated or oversized structure): the "
            "figure is a lower bound, so this request is not certified inside a body ceiling"
        )
    if measure.unmetered_images:
        report.notes.append(
            f"{measure.unmetered_images} image(s) are not base64 data URIs — their size is unknown"
        )

    if measure.body_scope != BODY_SCOPE_WHOLE and measure.body_bytes:
        detail = (f"{measure.tool_count:,} tool schema(s) are not passed to this surface"
                  if measure.tool_count else "the tool schemas are not visible here")
        report.notes.append(
            f"body figure covers {measure.body_scope} only ({detail}), so it is a LOWER bound "
            "on what the provider receives — the pinned body ceilings are whole-request numbers"
        )

    if not resolution.found:
        report.coverage = "no-row"
        report.notes.append("no measured row for this provider — nothing was checked")
        return report
    if not (resolution.row or {}).get("limits"):
        # Kept as UNKNOWN: no ceiling was checked. Evaluation still runs so the row's
        # "largest accepted" advisory can be shown.
        report.coverage = "no-limits"
        report.notes.append(
            f"no numeric ceiling is known for {resolution.key} — no probe on record bound this "
            "host, so this request was not checked against one"
        )

    if resolution.host_mismatch and report.coverage == "measured":
        report.coverage = "host-mismatch"

    findings = evaluate(measure, resolution)
    body_spec = (((resolution.row or {}).get("limits")) or {}).get(BODY)
    body_cap = _finite_int(body_spec.get("value")) if isinstance(body_spec, dict) else None
    if (body_cap and measure.body_scope != BODY_SCOPE_WHOLE and not measure.body_incomplete
            and 0 < measure.body_bytes <= body_cap
            and measure.body_bytes > body_cap * BODY_SCOPE_MARGIN):
        # Inside the ceiling as far as this surface can see -- but the figure excludes the tool
        # schemas, and this close to the wall that is exactly the difference that matters.
        findings.append(Finding(
            BODY, measure.body_bytes, body_cap, "beyond_observed", "partial-scope", "provider",
            f"inside the body ceiling as far as this surface can see ({measure.body_scope}), but "
            f"at {round(100 * measure.body_bytes / body_cap)}% of {_human(body_cap)} with the tool "
            "schemas excluded the real body may cross it"))
    if measure.unmetered_images:
        # An image whose size we could not read must never sit behind an "all limits ok".
        findings.append(Finding(IMAGE_TOTAL, measure.image_total_bytes, None, "beyond_observed",
                                "unmetered", "provider",
                                f"{measure.unmetered_images} image(s) whose bytes could not be "
                                "measured (not a base64 data URI)"))
    token = evaluate_tokens(resolution.row, int(approx_input_tokens or 0), resolution,
                            ratio=token_warn_ratio)
    if token is not None:
        findings.append(token)
    report.findings = _sorted(findings)
    return report


def preflight(messages: Any, *, provider: str = "", model: str = "", mode: str = "warn",
              pin: Optional[Dict[str, Any]] = None, approx_input_tokens: int = 0,
              token_warn_ratio: float = 0.9, max_dimension: int = 8000,
              apply: bool = False, system_prompt: Any = "", request_body: Any = None,
              tool_count: int = 0, base_url: str = "", resolve_as: str = "") -> Report:
    """Measure ``messages``, evaluate them against the pin, and optionally act.

    Returns a :class:`Report`. When ``apply`` is true (and ``mode`` is ``shrink``) the
    ``messages`` list is mutated in place to clear any predicted breach, and
    ``report.changed`` says whether it was touched.
    """
    measure = measure_messages(messages)
    measure.tool_count = max(0, _finite_int(tool_count) or 0)
    whole = estimate_request_body(request_body) if request_body is not None else None
    if whole is not None:
        # The middleware sees the dict Hermes is about to serialise: system prompt and tool
        # schemas included, which is what the pin's body ceilings describe.
        measure.body_bytes = whole
        measure.body_scope = BODY_SCOPE_WHOLE
    elif system_prompt:
        # _str_size returns (bytes, chars, non-ascii); the first is the byte figure.
        measure.body_bytes += int(_str_size(str(system_prompt))[0])
        measure.body_scope = "messages+system"
    report = assess(measure, provider=provider, model=model, mode=mode, pin=pin,
                    base_url=base_url, resolve_as=resolve_as,
                    approx_input_tokens=approx_input_tokens, token_warn_ratio=token_warn_ratio)
    if not apply or mode != "shrink":
        return report

    # The shrink tail re-evaluates the rewritten payload, so it needs the row again (assess()
    # keeps its resolution to itself).
    resolution = resolve(pin if pin is not None else load_pin(), resolve_as or provider, model,
                         base_url=base_url)
    actions = plan_actions(measure, report.findings)
    if not actions:
        return report
    taken, fresh = apply_actions(messages, actions, measure, max_dimension=max_dimension)
    if taken:
        report.actions = taken
        report.measure = fresh.as_dict()
        report.findings = _sorted(evaluate(fresh, resolution))
        report.changed = True
    else:
        # Say what was tried and what is known; never assert a cause that was not measured.
        tried = ", ".join(str(a.get("action")) for a in actions)
        report.notes.append(
            f"no action taken: {tried} changed nothing. Core's image shrink only rewrites "
            "parts over 4 MiB or max_dimension, so a byte-budget breach across many medium "
            "images needs images retired, not re-encoded"
        )
    if report.changed and report.worst == "breach":
        report.notes.append(
            "a rewrite was applied and the payload is still over a measured wall — "
            "it was not made to fit"
        )
    return report


def _sorted(findings: List[Finding]) -> List[Finding]:
    order = {"breach": 0, "beyond_observed": 1, "ok": 2}
    return sorted(findings, key=lambda f: (order.get(f.severity, 3), -(f.limit or 0)))


def human_bytes(value: Any) -> str:
    return _human(value)


def describe_finding(finding: Any) -> str:
    """One-line, human-readable finding — used in log lines and the CLI."""
    if isinstance(finding, dict):
        key = finding.get("key")
        value = finding.get("value")
        limit = finding.get("limit")
        severity = finding.get("severity")
        note = finding.get("note")
        basis = finding.get("basis") or ""
        factor = float(finding.get("factor") or 1.0)
    else:
        key, value, limit, severity, note = finding.key, finding.value, finding.limit, finding.severity, finding.note
        basis, factor = finding.basis, float(finding.factor or 1.0)
    if key in (ITEMS, TOKENS):
        measured, cap = f"{value:,}", f"{limit:,}"  # counts, not bytes
    else:
        measured, cap = _human(value), _human(limit)
    metered = ""
    if basis and basis not in ("decoded", "count", "body"):
        metered = f" [metered as {basis}" + (f" x{factor:g}" if factor != 1.0 else "") + "]"
    text = f"{severity}: {key} {measured} vs limit {cap}{metered}"
    if note:
        text += f" ({note})"
    return text


def format_report(report: "Report") -> str:
    """Multi-line rendering for the CLI / slash command."""
    measure = report.measure or {}
    lines = [
        f"{report.provider or '?'} / {report.model or '?'}  (pin row: {report.pin_key or '—'}, "
        f"match: {report.match}, mode: {report.mode})",
        f"  messages={measure.get('messages', 0)}  images={measure.get('images', 0)}"
        + (f" ({measure.get('unmetered_images')} unsized)" if measure.get("unmetered_images") else ""),
        f"  image bytes: total={_human(measure.get('image_total_bytes', 0))}"
        f"  largest={_human(measure.get('image_max_item_bytes', 0))}",
        f"  body: {_human(measure.get('body_bytes', 0))} (estimated, {measure.get('basis', 'estimate')})",
    ]
    for note in report.notes or []:
        lines.append(f"  note: {note}")
    moved = [f for f in (report.findings or []) if f.severity != "ok"]
    if moved:
        lines.append("  verdict: " + report.worst.upper())
        for finding in moved:
            lines.append("    - " + describe_finding(finding))
    else:
        # "OK" only when a ceiling really was checked; otherwise the outcome says UNKNOWN
        # and why (no row, no numeric ceiling, unreadable pin, unmeasurable payload).
        lines.append("  verdict: " + report.outcome)
    if report.actions:
        for action in report.actions:
            lines.append(f"  action: {action}")
    if report.changed:
        lines.append("  payload rewritten to fit")
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# state (last findings, counters, calibration)
# --------------------------------------------------------------------------------------

STATE_FILE = Path.home() / ".hermes" / "payload-guard" / "state.json"
STATE_ENV = "HERMES_PAYLOAD_GUARD_STATE"
STATE_KEEP = 50
FALSE_POSITIVE_KEEP = 20


def state_path(path: Any = None) -> Path:
    if path:
        return Path(str(path))
    import os

    override = os.environ.get(STATE_ENV, "").strip()
    return Path(override) if override else STATE_FILE


def load_state(path: Any = None) -> Dict[str, Any]:
    target = state_path(path)
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except Exception:
        return {"version": 1}


def _write_json(target: Path, payload: Dict[str, Any]) -> None:
    """Write JSON without a predictable temp name and without following a symlink.

    O_EXCL + O_NOFOLLOW on a pid/random name means a pre-planted symlink at the temp path
    cannot turn a recorded breach into a write to an arbitrary file, and the symlink check
    before the replace keeps ``state.json`` itself from becoming a pointer.
    """
    data = json.dumps(payload, indent=1, ensure_ascii=False)
    temp_file = target.with_name(f"{target.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    handle = os.fdopen(os.open(temp_file, flags, 0o600), "w", encoding="utf-8")
    try:
        with handle:
            handle.write(data)
        if target.is_symlink():
            raise OSError(f"refusing to replace a symlink: {target}")
        os.replace(temp_file, target)
    except Exception:
        try:
            # Bounded and explicit: the temp file is one we just created with O_EXCL inside
            # the resolved plugin state directory, so this can only remove our own litter.
            confined = (temp_file.parent == target.parent
                        and temp_file.name.startswith(target.name + ".")
                        and not temp_file.is_symlink())
            if confined:
                os.unlink(temp_file)
        except Exception:
            pass
        raise


@contextmanager
def _state_lock(path: Any = None):
    """Serialise the read-modify-write: hooks run on host daemon threads, so two writers
    can otherwise lose each other's counters, and a lock file is cheap."""
    handle = None
    try:
        target = state_path(path)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        handle = open(target.with_name(target.name + ".lock"), "a+", encoding="utf-8")
        try:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except Exception:  # no fcntl: still better than nothing
            pass
    except Exception as exc:
        logger.debug("payload-guard: no state lock: %s", exc)
        handle = None
    try:
        yield
    finally:
        if handle is not None:
            try:
                handle.close()
            except Exception:
                pass


def _save_state(state: Dict[str, Any], path: Any = None) -> None:
    target = state_path(path)
    try:
        if target.is_symlink() or (target.exists() and not target.is_file()):
            logger.warning(
                "payload-guard: refusing to write state — %s is not a regular file", target
            )
            return
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        state["updated_at"] = _utcnow()
        _write_json(target, state)
    except Exception as exc:  # state is best-effort, never fatal
        logger.debug("payload-guard: could not save state: %s", exc)


def _utcnow() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def record(report: "Report", path: Any = None) -> None:
    """Append a non-trivial report to the state file."""
    with _state_lock(path):
        _record_locked(report, path)


def _record_locked(report: "Report", path: Any = None) -> None:
    state = load_state(path)
    state["version"] = 1
    state["calls"] = int(state.get("calls") or 0) + 1
    worst = report.worst
    if worst == "breach":
        state["breaches"] = int(state.get("breaches") or 0) + 1
    if report.changed:
        state["rewrites"] = int(state.get("rewrites") or 0) + 1
    detail = "; ".join(
        describe_finding(f) for f in (report.findings or []) if f.severity != "ok"
    ) or ("within limits" if report.worst == "ok" else report.outcome)
    entry = {
        "ts": _utcnow(),
        "provider": report.provider,
        "model": report.model,
        "pin_key": report.pin_key,
        "match": report.match,
        "mode": report.mode,
        "worst": worst,
        "coverage": report.coverage,
        "detail": detail,
        "measure": report.measure,
        "actions": report.actions,
        "changed": bool(report.changed),
        "notes": list(report.notes),
    }
    state["last"] = ([entry] + list(state.get("last") or []))[:STATE_KEEP]
    _save_state(state, path)


def record_rejection(entry: Dict[str, Any], path: Any = None) -> None:
    """Record how a call actually ended, in the direction the ledger used to be blind to.

    ``outcome`` is ``rejected-as-predicted`` (we called that wall) or ``missed-wall`` (no
    wall predicted, yet the provider refused the request — the case that used to leave no
    trace at all, because the post hook only fires on success).
    """
    outcome = str(entry.get("outcome") or "")
    counter = {"rejected-as-predicted": "rejected_as_predicted",
               "missed-wall": "missed_walls"}.get(outcome)
    with _state_lock(path):
        state = load_state(path)
        state["version"] = 1
        if counter:
            state[counter] = int(state.get(counter) or 0) + 1
        record_entry = {"ts": entry.get("ts") or _utcnow(), **entry}
        state["rejection_last"] = ([record_entry] + list(state.get("rejection_last") or [])
                                   )[:FALSE_POSITIVE_KEEP]
        _save_state(state, path)


def record_false_positive(entry: Dict[str, Any], path: Any = None) -> None:
    """A predicted breach that the provider accepted — the pin is conservative for this call."""
    with _state_lock(path):
        _record_false_positive_locked(entry, path)


def _record_false_positive_locked(entry: Dict[str, Any], path: Any = None) -> None:
    state = load_state(path)
    state["version"] = 1
    state["false_positives"] = int(state.get("false_positives") or 0) + 1
    state["calls"] = int(state.get("calls") or 0) + 1
    state["false_positive_last"] = ([entry] + list(state.get("false_positive_last") or []))[:FALSE_POSITIVE_KEEP]
    _save_state(state, path)


def _human(value: Any) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return str(value)
    for unit, factor in (("GiB", 1024 ** 3), ("MiB", 1024 ** 2), ("KiB", 1024)):
        if abs(number) >= factor:
            return f"{number / factor:,.1f} {unit}"
    return f"{number:,} B"
