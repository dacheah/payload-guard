"""Glue tests for payload-guard: registration, the hook and the middleware contract.

These do not need Hermes: they drive the module with a stub context, which is the only
thing the plugin loader hands us anyway.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parents[1]
if str(PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(PLUGIN_DIR))


def load_plugin():
    spec = importlib.util.spec_from_file_location("payload_guard_plugin", PLUGIN_DIR / "__init__.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StubCtx:
    def __init__(self):
        self.hooks = []
        self.middleware = []
        self.commands = []
        self.cli = []

    def register_hook(self, name, callback):
        self.hooks.append((name, callback))

    def register_middleware(self, kind, callback):
        self.middleware.append((kind, callback))

    def register_command(self, *args, **kwargs):
        self.commands.append((args, kwargs))

    def register_cli_command(self, *args, **kwargs):
        self.cli.append((args, kwargs))


def data_uri(size: int) -> str:
    return "data:image/png;base64," + base64.b64encode(b"\x00" * size).decode()


def messages_with(images: int, size: int = 1000):
    return [{"role": "user",
             "content": [{"type": "image_url", "image_url": {"url": data_uri(size)}}
                         for _ in range(images)]}]


@pytest.fixture()
def plugin(tmp_path, monkeypatch):
    module = load_plugin()
    monkeypatch.setenv("HERMES_PAYLOAD_GUARD_STATE", str(tmp_path / "state.json"))
    module._PENDING.clear()
    module._LAST.clear()
    module.g._PIN_CACHE.update({"path": None, "mtime": None, "data": None})
    return module


def state(plugin) -> dict:
    path = Path(os.environ["HERMES_PAYLOAD_GUARD_STATE"])
    return json.loads(path.read_text()) if path.exists() else {}


def test_register_wires_the_hook_commands_and_skips_the_middleware_in_warn_mode(plugin, monkeypatch):
    monkeypatch.setattr(plugin, "_load_config", lambda: dict(plugin.DEFAULT_CONFIG))
    ctx = StubCtx()
    plugin.register(ctx)

    assert [name for name, _ in ctx.hooks] == [
        "pre_api_request", "post_api_request", "api_request_error"
    ]
    # warn mode must NOT register the middleware: registering it makes Hermes deep-copy
    # the whole payload on every API call — a cost worth paying only when we may rewrite
    assert ctx.middleware == []
    assert len(ctx.commands) == 1 and len(ctx.cli) == 1


def test_register_takes_the_middleware_in_shrink_mode(plugin, monkeypatch):
    monkeypatch.setattr(plugin, "_load_config", lambda: {**plugin.DEFAULT_CONFIG, "mode": "shrink"})
    ctx = StubCtx()
    plugin.register(ctx)
    assert [kind for kind, _ in ctx.middleware] == ["llm_request"]


def test_register_is_inert_when_disabled(plugin, monkeypatch):
    monkeypatch.setattr(plugin, "_load_config", lambda: {**plugin.DEFAULT_CONFIG, "enabled": False})
    ctx = StubCtx()
    plugin.register(ctx)
    assert ctx.hooks == [] and ctx.middleware == []


def test_hook_returns_nothing_but_exposes_the_report(plugin):
    result = plugin.on_pre_api_request(
        session_id="s1", api_call_count=1, provider="openai", model="gpt-4.1-mini",
        request_messages=messages_with(18, 2_053_887), approx_input_tokens=5000,
    )
    assert result is None  # pre_api_request cannot cancel or rewrite anything
    report = plugin._LAST["report"]
    assert report["worst"] == "breach"
    assert report["findings"][0]["key"] == "image_total_bytes"
    assert state(plugin)["breaches"] == 1


def test_hook_falls_back_to_conversation_history_when_parts_are_absent(plugin):
    plugin.on_pre_api_request(session_id="s1b", api_call_count=1, provider="fireworks",
                              model="kimi-k2p6", conversation_history=messages_with(61, 4_000))
    assert plugin._LAST["report"]["worst"] == "breach"


def test_hook_measures_but_records_nothing_when_all_is_well(plugin):
    plugin.on_pre_api_request(session_id="s1c", api_call_count=2, provider="openai",
                              model="gpt-4.1-mini", request_messages=messages_with(2, 1000))
    assert plugin._LAST["report"]["worst"] == "ok"
    assert state(plugin) == {}


def test_middleware_returns_none_when_nothing_changed(plugin, monkeypatch):
    monkeypatch.setattr(plugin, "_load_config", lambda: {**plugin.DEFAULT_CONFIG, "mode": "shrink"})
    request = {"model": "qwen3.8-flash", "messages": messages_with(2, 1000)}
    assert plugin.on_llm_request(request=request, provider="alibaba", model="qwen3.8-flash") is None


def test_middleware_rewrites_only_when_it_can_fix_the_payload(plugin, monkeypatch):
    monkeypatch.setattr(plugin, "_load_config", lambda: {**plugin.DEFAULT_CONFIG, "mode": "shrink"})
    def carrier(count: int, role: str) -> dict:
        return {"role": role,
                "content": [{"type": "image_url",
                             "image_url": {"url": "data:image/png;base64," + "A" * 533_000}}]
                * count}

    messages = [carrier(84, "tool") for _ in range(3)]   # historic tool results
    messages.append(carrier(1, "user"))                  # the live turn: 253 vs a cap of 250
    result = plugin.on_llm_request(
        request={"model": "qwen3.8-flash", "messages": messages},
        provider="alibaba", model="qwen3.8-flash", session_id="s2", api_call_count=3,
    )
    assert isinstance(result, dict) and "request" in result
    assert plugin._LAST["report"]["changed"] is True
    assert state(plugin)["rewrites"] == 1


def test_middleware_leaves_an_unfixable_breach_alone(plugin, monkeypatch):
    monkeypatch.setattr(plugin, "_load_config", lambda: {**plugin.DEFAULT_CONFIG, "mode": "shrink"})
    request = {"model": "qwen3.8-flash", "messages": messages_with(251, 400_000)}
    assert plugin.on_llm_request(request=request, provider="alibaba", model="qwen3.8-flash") is None
    assert plugin._LAST["report"]["worst"] == "breach"


def test_middleware_is_inert_in_warn_mode_even_if_it_gets_called(plugin, monkeypatch):
    monkeypatch.setattr(plugin, "_load_config", lambda: dict(plugin.DEFAULT_CONFIG))
    request = {"model": "qwen3.8-flash", "messages": messages_with(251, 400_000)}
    before = json.dumps(request["messages"])
    assert plugin.on_llm_request(request=request, provider="alibaba", model="qwen3.8-flash") is None
    assert json.dumps(request["messages"]) == before


def test_post_api_request_scores_a_prediction_that_was_accepted(plugin):
    plugin.on_pre_api_request(session_id="s3", api_call_count=7, api_request_id="req-7",
                              provider="openai", model="gpt-4.1-mini",
                              request_messages=messages_with(18, 2_053_887))
    plugin.on_post_api_request(session_id="s3", api_call_count=7, api_request_id="req-7",
                               provider="openai", model="gpt-4.1-mini")
    data = state(plugin)
    assert data["false_positives"] == 1
    assert data["false_positive_last"][0]["keys"] == ["image_total_bytes"]
    assert plugin._PENDING == {}


def test_post_api_request_ignores_calls_we_predicted_nothing_for(plugin):
    plugin.on_post_api_request(session_id="s3b", api_call_count=1, provider="openai",
                               model="gpt-4.1-mini")
    assert state(plugin) == {}


def test_cli_parser_and_handler_reproduce_the_measured_openai_pair(plugin, capsys):
    """Through argparse, the way Hermes invokes it: the 400 row exits 1, the 200 row exits 0."""
    import argparse

    parser = argparse.ArgumentParser(prog="hermes payload-guard")
    plugin.setup_cli(parser)

    args = parser.parse_args(["check", "--provider", "openai", "--model", "gpt-4.1-mini",
                              "--images", "18", "--image-bytes", "2053887"])
    assert plugin.handle_cli(args) == 1  # the measured 400
    assert "BREACH" in capsys.readouterr().out

    args = parser.parse_args(["check", "--provider", "openai", "--model", "gpt-4.1-mini",
                              "--images", "17", "--image-bytes", "2053887"])
    assert plugin.handle_cli(args) == 0  # the measured 200
    assert "OK" in capsys.readouterr().out

    # bare invocation is status, and it must not explode
    assert plugin.handle_cli(parser.parse_args([])) == 0
    assert "payload-guard:" in capsys.readouterr().out


def test_check_slash_and_cli_agree(plugin):
    args = {"provider": "fireworks", "model": "kimi-k2p6", "images": 61, "image_bytes": 4_000}
    slash = plugin.handle_slash("check --provider fireworks --model kimi-k2p6 --images 61 --image-bytes 4000")
    cli = plugin.g.format_report(plugin._check_report(args))
    assert "BREACH" in slash and "BREACH" in cli


def test_slash_status_reports_pin_and_history(plugin, monkeypatch):
    monkeypatch.setattr(plugin, "_load_config", lambda: dict(plugin.DEFAULT_CONFIG))
    plugin.on_pre_api_request(session_id="s4", api_call_count=1, provider="openai",
                              model="gpt-4.1-mini", request_messages=messages_with(18, 2_053_887))
    text = plugin.handle_slash("status")
    assert "payload-guard: mode=warn" in text
    assert "openai/gpt-4.1-mini" in text
    assert "payload-walls" in text


def test_slash_providers_lists_the_covered_hosts(plugin):
    text = plugin.handle_slash("providers")
    assert "openai" in text and "alibaba" in text and "fireworks" in text


def test_slash_never_raises_on_junk(plugin):
    assert plugin.handle_slash("check --images not-a-number").startswith("payload-guard:")


def test_pin_is_reproducible_from_the_published_dataset(plugin):
    """The vendored pin must be a faithful, dated extract of the repo's limits.json."""
    import pin_limits

    pin_file = Path(pin_limits.HERE) / "limits.pin.json"
    assert pin_file.exists()
    data = json.loads(pin_file.read_text())
    assert data["pin_version"] == 1
    assert data["source"]["repo"].endswith("payload-walls")
    assert data["providers"]

    repo = Path("/home/dan/llm-request-budgets/limits.json")
    if not repo.exists():
        pytest.skip("published dataset not checked out on this machine")
    # pin_limits --check re-derives the pin from the repo dataset and diffs it
    assert pin_limits.main([str(repo), "--out", str(pin_file), "--check", "--quiet"]) == 0


def test_api_request_error_records_the_direction_the_ledger_was_blind_to(plugin, monkeypatch, tmp_path):
    """A false negative (predicted fine, provider rejected) must leave a record.

    post_api_request only fires once a response was obtained, so before this hook the state
    file could only ever look healthy: the dangerous direction was silently discarded.
    """
    state_file = tmp_path / "state.json"
    monkeypatch.setattr(plugin, "_load_config",
                        lambda: {**plugin.DEFAULT_CONFIG, "state_path": str(state_file)})
    plugin.on_pre_api_request(
        request_messages=[{"role": "user", "content": "hello"}],
        system_prompt="", api_call_count=1, api_request_id="1:api:1",
        session_id="s1", provider="openrouter", model="unmeasured-model",
    )
    plugin.on_api_request_error(
        session_id="s1", provider="openrouter", model="unmeasured-model",
        api_request_id="1:api:1", api_call_count=1, status_code=413, retry_count=0,
        error={"type": "request_too_large", "message": "Request entity too large"},
    )
    state = json.loads(state_file.read_text())
    assert state["missed_walls"] == 1
    entry = state["rejection_last"][0]
    assert entry["outcome"] == "missed-wall" and entry["status_code"] == 413
