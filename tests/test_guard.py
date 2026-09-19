"""payload-guard engine tests.

The interesting cases are not invented: each one replays a specific probe row from the
published dataset (same image sizes, same counts, same accept/reject outcome), so a
regression in the estimator or the limits shows up as a disagreement with ground truth
measured against the live API.

Run:  python -m pytest tests/ -q
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PLUGIN_DIR = HERE.parent
sys.path.insert(0, str(PLUGIN_DIR))

import guard as g  # noqa: E402

REPO_LIMITS = Path("/home/dan/llm-request-budgets/limits.json")
PIN = g.load_pin()

# --- ground truth pulled from the dataset ---------------------------------------------
JPEG_SMALL = 2_053_887          # openai: 17 x this accepted, 18 x this rejected
JPEG_LARGE = 12_144_445         # openai: 8 x this accepted (97.16 MB raw / 129.5 MB body)


def data_uri(payload_bytes: int, mime: str = "image/jpeg") -> str:
    """A data URI whose decoded size is exactly ``payload_bytes`` (deterministic bytes)."""
    raw = bytes(payload_bytes)  # b"\x00" * n — length is what matters here
    return f"data:{mime};base64," + base64.b64encode(raw).decode("ascii")


def user_message_with_images(count: int, payload_bytes: int, text: str = "describe these") -> dict:
    return {
        "role": "user",
        "content": [{"type": "text", "text": text}]
        + [{"type": "image_url", "image_url": {"url": data_uri(payload_bytes)}} for _ in range(count)],
    }


def tool_message_with_images(count: int, payload_bytes: int, text: str = "screenshot") -> dict:
    """A tool-result carrier: where historic images accumulate in a real conversation."""
    return {
        "role": "tool",
        "content": [{"type": "text", "text": text}]
        + [{"type": "image_url", "image_url": {"url": data_uri(payload_bytes)}} for _ in range(count)],
    }


def measure_for(provider: str, model: str, messages: list) -> "g.Report":
    return g.preflight(messages, provider=provider, model=model, pin=PIN, mode="warn")


# --------------------------------------------------------------------------- estimator


def test_estimate_body_bytes_matches_json_dumps():
    payloads = [
        {"a": 1, "b": "x" * 10, "c": [1, 2, 3], "d": None, "e": True},
        [{"role": "user", "content": "hello"}] * 5,
        {"messages": [user_message_with_images(3, 1000)]},
        {"nested": {"deep": {"deeper": ["ok", 12.5, False]}}},
    ]
    for payload in payloads:
        actual = len(json.dumps(payload, separators=(",", ":")))
        estimate, chars, _ = g.estimate_body_bytes(payload)
        assert abs(estimate - actual) / actual < 0.005, (payload, estimate, actual)
        assert chars > 0


def test_estimate_body_bytes_non_ascii_expansion():
    text = "日本語のテキスト" * 200
    payload = {"content": text}
    actual = len(json.dumps(payload, separators=(",", ":")))
    estimate, chars, nonascii = g.estimate_body_bytes(payload)
    assert chars >= len(text)  # text chars, plus the "content" key
    assert nonascii == sum(1 for ch in text if not ch.isascii())
    # ensure_ascii escapes every non-ascii char to \uXXXX, which the model accounts for
    assert abs(estimate - actual) / actual < 0.005, (estimate, actual)


def test_estimate_is_exact_for_base64_images():
    messages = [user_message_with_images(4, 9173)]
    actual = len(json.dumps(messages, separators=(",", ":")))
    estimate, _, _ = g.estimate_body_bytes(messages)
    assert estimate == actual


# --------------------------------------------------------------------------- measurement


def test_measure_image_sizes_are_exact():
    messages = [user_message_with_images(3, 2_053_887)]
    measure = g.measure_messages(messages)
    assert measure.images == 3
    assert measure.image_total_bytes == 3 * 2_053_887
    assert measure.image_max_item_bytes == 2_053_887
    assert measure.image_total_encoded_bytes == 3 * ((2_053_887 + 2) // 3 * 4)
    assert measure.unmetered_images == 0


def test_measure_anthropic_native_and_url_images():
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": base64.b64encode(b"x" * 1000).decode()}},
                {"type": "image", "source": {"type": "url", "url": "https://example.com/a.png"}},
            ],
        }
    ]
    measure = g.measure_messages(messages)
    assert measure.images == 2
    assert measure.image_total_bytes == 1000
    assert measure.unmetered_images == 1  # a URL image has no size we can know


def test_measure_counts_unsized_unknown_parts():
    measure = g.measure_messages([{"role": "user", "content": [{"type": "image_base64", "image_base64": "unknown-format"}]}])
    assert measure.images == 1
    assert measure.unmetered_images == 1


def test_measure_ignores_text_only_content():
    measure = g.measure_messages([{"role": "user", "content": "just text"}])
    assert measure.images == 0
    assert measure.body_bytes > 0


# --------------------------------------------------------------------------- openai


def test_openai_ground_truth_pair_small_images():
    """17 x 2,053,887 B got a 200; 18 x the same got the 400 'Total image size is 50.56MB'."""
    accepted = measure_for("openai", "gpt-4.1-mini", [user_message_with_images(17, JPEG_SMALL)])
    assert accepted.worst == "ok", accepted.summary()
    assert accepted.breaches == []

    rejected = measure_for("openai", "gpt-4.1-mini", [user_message_with_images(18, JPEG_SMALL)])
    assert rejected.worst == "breach", rejected.summary()
    finding = rejected.breaches[0]
    assert finding.key == g.IMAGE_TOTAL
    assert finding.kind == "stated_in_error"
    assert "normalised copy" in finding.note


def test_openai_large_image_case_is_the_documented_false_positive():
    """8 x 12,144,445 B was accepted by the live API while our rule predicts a breach.

    This is the known conservative case: the vendor downscales large images before
    counting them. It must stay *flagged* (never silently passed) and the note must say
    why, because the plugin counts these as false positives rather than hiding them.
    """
    report = measure_for("openai", "gpt-4.1-mini", [user_message_with_images(8, JPEG_LARGE)])
    assert report.worst == "breach"
    assert "false positive" in report.breaches[0].note


def test_openai_has_no_count_or_per_image_limit_below_the_budget():
    report = measure_for("openai", "gpt-4.1-mini", [user_message_with_images(100, 9_000)])
    assert report.worst == "ok", report.summary()


# --------------------------------------------------------------------------- other hosts


def test_alibaba_item_and_count_caps():
    accepted = measure_for("alibaba", "qwen3.8-flash", [user_message_with_images(250, 500_000)])
    assert accepted.worst == "ok", accepted.summary()

    too_many = measure_for("alibaba", "qwen3.8-flash", [user_message_with_images(251, 500_000)])
    assert too_many.worst == "breach"
    assert [f.key for f in too_many.breaches] == [g.ITEMS]

    # The count wall is a stated cap the probes hit, so it stays hard. The per-item figure
    # is labelled "bracket": the dataset says the vendor's wording and the observation both
    # fit it, so it must not be a hard breach claim.
    assert too_many.breaches and too_many.breaches[0].kind == "resolved_cap"

    oversize_item = measure_for("alibaba", "qwen3.8-flash", [user_message_with_images(1, 21_000_000)])
    assert oversize_item.worst == "advisory"
    assert oversize_item.advisories[0].key == g.ITEM
    assert any("vendor wording" in f.note for f in oversize_item.advisories)


def test_alibaba_big_body_is_not_a_breach():
    """96 images / 512 MiB body was accepted — there is no body wall to trip on."""
    messages = [user_message_with_images(96, 5_600_000)]
    report = measure_for("alibaba", "qwen3.8-flash", messages)
    assert report.measure["body_bytes"] > 500 * 1024 * 1024
    assert report.breaches == []


def test_anthropic_body_and_item_caps():
    # the accepted probe row: 6 images, body 33,452,885 B (< the 32 MiB cap)
    accepted = measure_for("anthropic", "claude-haiku-4-5-20251001",
                           [user_message_with_images(6, 4_186_000)])
    assert accepted.breaches == [], accepted.summary()
    big_body = [{"role": "user", "content": "x" * 33_600_000}]
    report = measure_for("anthropic", "claude-haiku-4-5-20251001", big_body)
    assert report.worst == "breach"
    assert report.breaches[0].key == g.BODY
    # the rejected probe row: 6 images, body 33,571,037 B (> the same cap)
    rejected = measure_for("anthropic", "claude-haiku-4-5-20251001",
                           [user_message_with_images(6, 4_200_000)])
    assert g.BODY in [f.key for f in rejected.breaches]
    assert measure_for("anthropic", "claude-haiku-4-5-20251001", [user_message_with_images(1, 10_485_760)]).breaches == []
    oversize = measure_for("anthropic", "claude-haiku-4-5-20251001", [user_message_with_images(1, 10_485_761)])
    assert oversize.breaches[0].key == g.ITEM


def test_fireworks_count_cap():
    assert measure_for("fireworks", "kimi-k2p6", [user_message_with_images(60, 4_000)]).breaches == []
    report = measure_for("fireworks", "kimi-k2p6", [user_message_with_images(61, 4_000)])
    assert [f.key for f in report.breaches] == [g.ITEMS]


def test_deepinfra_count_cap():
    assert measure_for("deepinfra", "Inkling-Small", [user_message_with_images(8, 1_000)]).breaches == []
    report = measure_for("deepinfra", "Inkling-Small", [user_message_with_images(11, 1_000)])
    assert [f.key for f in report.breaches] == [g.ITEMS]


def test_minimax_body_and_item_caps():
    assert measure_for("minimax", "MiniMax-M3", [{"role": "user", "content": "x" * 126_800_000}]).breaches == []
    report = measure_for("minimax", "MiniMax-M3", [{"role": "user", "content": "x" * 135_000_000}])
    assert [f.key for f in report.breaches] == [g.BODY]


def test_ollama_cloud_bracket_stays_advisory():
    """The dataset's own note says 'bracket only (15.9-16.5 MiB) - the cap is not exact', so
    a size the probes never actually rejected must not come back as a hard breach (with an
    exit status a script can gate on)."""
    assert measure_for("ollama-cloud", "gemma4:31b", [{"role": "user", "content": "x" * 16_700_000}]).breaches == []
    report = measure_for("ollama-cloud", "gemma4:31b", [{"role": "user", "content": "x" * 17_300_000}])
    assert report.worst == "advisory"
    assert any(f.key == g.BODY and "not exact" in f.note for f in report.advisories)


def test_upstage_images_are_a_capability_not_a_limit():
    report = measure_for("upstage", "solar-pro4", [user_message_with_images(1, 1_000)])
    assert report.worst == "advisory"
    assert any("not allowed" in f.note for f in report.advisories)
    assert [f.key for f in report.advisories] == [g.ITEMS]


def test_xai_documented_limit_is_advisory_not_hard():
    report = measure_for("xai", "grok-4", [user_message_with_images(1, 25_000_000)])
    assert report.worst == "advisory", report.summary()


def test_unmeasured_host_has_no_limits():
    report = measure_for("openai-codex", "gpt-5.6-luna", [user_message_with_images(4, 1_000_000)])
    assert report.findings == []
    assert any("no numeric ceiling is known" in n for n in report.notes)


def test_unknown_provider_is_inert_not_wrong():
    report = measure_for("stepfun", "step-3", [user_message_with_images(4, 1_000_000)])
    assert report.findings == []
    assert report.notes[-1].startswith("no measured row")


def test_zai_beyond_observed_is_advisory_but_never_ok():
    """zai has no resolved cap; 223 MiB was rejected, 192.6 MiB accepted.

    No ceiling means the verdict is UNKNOWN -- the advisory rides along, but it must not be
    reported as "inside every measured ceiling".
    """
    report = measure_for("zai", "glm-4.5v", [{"role": "user", "content": "x" * 220_000_000}])
    assert report.coverage == "no-limits"
    assert report.worst == "unknown"
    assert report.outcome.startswith("UNKNOWN")
    assert report.advisories[0].key == g.BODY
    assert report.advisories[0].kind == "accepted_max"


# --------------------------------------------------------------------------- tokens


def test_token_budget_only_hard_on_the_measured_model():
    matched = g.preflight(
        [{"role": "user", "content": "x" * 10}],
        provider="gemini",
        model="gemini-3.5-flash-lite",
        pin=PIN,
        mode="warn",
        approx_input_tokens=1_100_000,
    )
    assert [f.key for f in matched.breaches] == [g.TOKENS]

    different_model = g.preflight(
        [{"role": "user", "content": "x" * 10}],
        provider="gemini",
        model="gemini-3.0-pro",
        pin=PIN,
        mode="warn",
        approx_input_tokens=1_100_000,
    )
    assert different_model.breaches == []
    assert different_model.advisories[0].key == g.TOKENS


def test_token_warn_ratio_raises_an_advisory_short_of_the_cap():
    report = g.preflight(
        [{"role": "user", "content": "x"}],
        provider="gemini",
        model="gemini-3.5-flash-lite",
        pin=PIN,
        mode="warn",
        approx_input_tokens=960_000,
    )
    assert report.worst == "advisory"


# --------------------------------------------------------------------------- resolution


def test_aliases_resolve_and_flag_region_mismatch():
    resolution = g.resolve(PIN, "alibaba-cn", "qwen3.8-flash")
    assert resolution.key == "alibaba"
    assert resolution.region_mismatch is True
    report = g.preflight([{"role": "user", "content": "x"}], provider="alibaba-cn", model="qwen3.8-flash", pin=PIN)
    assert any("region mismatch" in n for n in report.notes)


def test_provider_model_match_detection():
    assert g.resolve(PIN, "openai", "gpt-4.1-mini").match == "provider+model"
    assert g.resolve(PIN, "openai", "gpt-5.9-ultra").match == "provider"
    assert g.resolve(PIN, "fireworks", "accounts/fireworks/models/kimi-k2p6").match == "provider+model"


def test_pin_rows_are_honest_about_confidence():
    for key, row in (PIN.get("providers") or {}).items():
        for limit_key, spec in (row.get("limits") or {}).items():
            assert spec["kind"] in {"resolved_cap", "stated_in_error", "documented",
                                    "bracket", "capability"}, (key, limit_key)
            if spec["kind"] == "bracket":
                # a demoted figure must say why it was demoted
                assert spec.get("note"), (key, limit_key)
            if row.get("confidence") == "unmeasured":
                assert not row.get("limits")


# --------------------------------------------------------------------------- actions


def test_drop_oldest_images_protects_user_uploads_and_the_live_turn():
    """Regression: a tool loop's live message is the tool result, so 'protect the last
    message' alone let shrink delete the photos the user had just attached."""
    messages = [
        {"role": "user", "content": [{"type": "image_url", "image_url": {"url": data_uri(1000)}}]},
        {"role": "assistant", "content": "ok"},
        tool_message_with_images(1, 1000),
        {"role": "user", "content": [{"type": "image_url", "image_url": {"url": data_uri(1000)}}, {"type": "text", "text": "and this"}]},
    ]
    removed = g.drop_oldest_images(messages, target_images=2)
    assert removed == 1                                    # stops at the target
    assert g.content_count(messages) == 2
    assert messages[0]["content"][0]["type"] == "image_url"   # oldest: a user upload, kept
    assert any(p.get("type") == "image_url" for p in messages[-1]["content"])  # live turn kept
    assert messages[2]["content"][0]["type"] == "text"        # the tool carrier is what went


def test_shrink_mode_rewrites_the_payload_to_fit():
    messages = [tool_message_with_images(84, 400_000) for _ in range(3)]
    messages.append(user_message_with_images(1, 400_000))  # 253 images, cap is 250
    report = g.preflight(messages, provider="alibaba", model="qwen3.8-flash", pin=PIN, mode="shrink",
                         apply=True)
    assert report.changed is True
    assert report.actions[0]["action"] == "drop_oldest_images"
    assert report.measure["images"] <= 250
    assert report.breaches == []
    assert g.content_count(messages) <= 250
    assert any(p.get("type") == "image_url" for p in messages[-1]["content"])  # live turn kept


def test_shrink_mode_refuses_to_delete_a_user_upload():
    """An unfixable breach is reported, not papered over -- and the user's own images are
    never the thing that gets sacrificed to make the number fit."""
    messages = [user_message_with_images(251, 400_000)]
    report = g.preflight(messages, provider="alibaba", model="qwen3.8-flash", pin=PIN, mode="shrink",
                         apply=True)
    assert report.changed is False
    assert report.breaches                      # still a breach, honestly
    assert g.content_count(messages) == 251     # nothing was taken
    assert any("no action taken" in n for n in report.notes)


def test_images_nested_in_anthropic_tool_results_are_measured():
    """Regression (HIGH): on the anthropic wire a tool result carries its images inside
    tool_result.content. A top-level-only walk measured 0 images and called the payload OK
    for a request Anthropic answers with a per-image 400."""
    nested = {
        "role": "user",
        "content": [{
            "type": "tool_result",
            "tool_use_id": "tu_1",
            "content": [
                {"type": "text", "text": "screenshot"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                             "data": "A" * 16_000_000}},
            ],
        }],
    }
    measure = g.measure_messages([nested])
    assert measure.images == 1
    assert measure.image_total_bytes == 12_000_000          # decoded, not the base64 length
    report = g.preflight([nested], provider="anthropic", model="claude-haiku-4-5", pin=PIN)
    assert report.measure["images"] == 1
    assert report.worst != "ok"                             # no more silent pass


def test_a_cyclic_payload_cannot_spin_the_measurement():
    """Regression (HIGH): one non-tree payload hung the hook worker forever (the host
    abandons a timed-out callback without joining it, so it burned a thread for the life of
    the process and skipped every later check)."""
    payload: dict = {"role": "user", "content": []}
    payload["content"].append(payload)                       # a true cycle
    measure = g.measure_messages([payload])
    assert measure.body_incomplete is True
    report = g.preflight([payload], provider="openai", model="gpt-4.1-mini", pin=PIN)
    assert report.coverage == "partial"
    assert report.worst != "ok"


def test_an_unusable_pin_is_unknown_never_ok(tmp_path):
    """Regression (HIGH): a pin that parsed but was the wrong shape enforced nothing while
    still printing ceilings."""
    bad = tmp_path / "limits.pin.json"
    bad.write_text(json.dumps({
        "pin_version": 1,
        "providers": {"deepseek": {"limits": {"body_bytes": {"value": "48 MiB",
                                                            "kind": "resolved_cap"}}}},
        "aliases": {},
    }))
    pin = g.load_pin(bad)
    assert pin.get("providers") == {}
    assert g.PIN_STATE["status"] == "invalid"
    report = g.preflight([{"role": "user", "content": "x" * 100}], provider="deepseek",
                         model="deepseek-flash", pin=pin)
    assert report.coverage == "pin-invalid"
    assert report.worst == "unknown"
    assert report.outcome.startswith("UNKNOWN")


def test_warn_mode_never_touches_the_payload():
    messages = [user_message_with_images(251, 400_000)]
    before = json.dumps(messages, separators=(",", ":"))
    report = g.preflight(messages, provider="alibaba", model="qwen3.8-flash", pin=PIN, mode="warn", apply=True)
    assert report.changed is False
    assert json.dumps(messages, separators=(",", ":")) == before


def test_shrink_images_is_safe_when_the_core_helper_is_absent():
    assert g.shrink_images([]) is False


def test_plan_actions_ignores_advisories():
    report = measure_for("zai", "glm-4.5v", [{"role": "user", "content": "x" * 220_000_000}])
    assert g.plan_actions(g.measure_messages([]), report.findings) == []


# --------------------------------------------------------------------------- state


def test_state_records_and_survives(tmp_path):
    state_file = tmp_path / "state.json"
    report = measure_for("fireworks", "kimi-k2p6", [user_message_with_images(61, 4_000)])
    g.record(report, state_file)
    g.record_false_positive({"ts": "t", "provider": "openai", "model": "gpt-4.1-mini", "keys": ["image_total_bytes"]}, state_file)

    state = g.load_state(state_file)
    assert state["calls"] == 2
    assert state["breaches"] == 1
    assert state["false_positives"] == 1
    assert state["last"][0]["provider"] == "fireworks"
    assert "breach" in state["last"][0]["detail"]
    assert state["false_positive_last"][0]["keys"] == ["image_total_bytes"]


def test_state_is_bounded(tmp_path):
    state_file = tmp_path / "state.json"
    for _ in range(60):
        g.record(measure_for("fireworks", "kimi-k2p6", [user_message_with_images(61, 4_000)]), state_file)
    assert len(g.load_state(state_file)["last"]) == g.STATE_KEEP


# --------------------------------------------------------------------------- pin integrity


@pytest.mark.skipif(not REPO_LIMITS.exists(), reason="published dataset not on this host")
def test_pin_is_faithful_to_the_published_dataset():
    """The vendored pin must be exactly what the repo's limits.json produces."""
    import pin_limits

    fresh = pin_limits.build(REPO_LIMITS, json.loads((PLUGIN_DIR / "aliases.json").read_text()))
    vendored = json.loads((PLUGIN_DIR / "limits.pin.json").read_text())
    assert fresh["providers"] == vendored["providers"], "pin has drifted from the dataset"
    assert fresh["aliases"] == vendored["aliases"]

# --------------------------------------------------------------------------------------
# residual 1: the body figure says what it covers, and only the middleware sees it whole
# --------------------------------------------------------------------------------------


def test_a_whole_request_figure_is_measured_when_the_surface_holds_the_dict():
    """The pin's body ceilings are whole-request numbers -- system prompt and tool schemas
    included -- so only the middleware surface can produce a whole-body figure, and there it
    must come from the request dict rather than from the messages alone."""
    messages = [{"role": "user", "content": "hello"}]
    request = {
        "model": "gpt-4.1-mini",
        "messages": messages,
        "tools": [{"type": "function", "function": {"name": "f", "description": "d" * 5_000}}],
        "timeout": 600,  # transport kwarg: passed to the client, never serialised
    }
    report = g.preflight(messages, provider="openai", model="gpt-4.1-mini", pin=PIN,
                         request_body=request)
    assert report.measure["body_scope"] == "whole-request"
    assert report.measure["body_bytes"] > 5_000            # the tool schema is counted
    assert not any("LOWER bound" in n for n in report.notes)
    without = {k: v for k, v in request.items() if k != "timeout"}
    assert report.measure["body_bytes"] == g.estimate_request_body(without)


def test_a_messages_only_figure_is_labelled_a_lower_bound():
    """The pre-flight hook never sees the tool schemas, so its figure understates the body --
    and every finding and note must say which figure it is."""
    report = g.preflight([{"role": "user", "content": "hello"}], provider="deepseek",
                         model="deepseek-flash", pin=PIN, system_prompt="S" * 4_000,
                         tool_count=40)
    assert report.measure["body_scope"] == "messages+system"
    assert report.measure["tool_count"] == 40
    assert any("LOWER bound" in n for n in report.notes)
    body = [f for f in report.findings if f.key == g.BODY]
    assert body, "deepseek has a body ceiling: the finding must exist"
    assert "covers messages+system only" in (body[0].note or "")


def test_a_partial_scope_figure_near_a_body_wall_is_not_reported_ok():
    """Inside the ceiling as far as this surface can see, but the tool schemas are missing
    from the figure: this close to the wall, that is the difference that matters."""
    cap = g._finite_int(PIN["providers"]["deepseek"]["limits"]["body_bytes"]["value"])
    report = g.preflight([{"role": "user", "content": "x" * int(cap * 0.8)}],
                         provider="deepseek", model="deepseek-flash", pin=PIN)
    assert report.measure["body_bytes"] <= cap
    assert report.worst == "advisory"
    assert [f for f in report.advisories if f.kind == "partial-scope"]


def test_a_request_that_did_not_go_to_the_measured_host_is_unknown():
    """A ceiling measured on api.openai.com says nothing about a gateway or a regional
    endpoint: the host is part of the measurement's scope."""
    wrong = g.preflight([{"role": "user", "content": "x"}], provider="openai",
                        model="gpt-4.1-mini", pin=PIN,
                        base_url="https://my-llm-gateway.internal/v1")
    assert wrong.coverage == "host-mismatch"
    assert wrong.worst == "unknown"
    assert "not checked" in wrong.outcome
    assert any("my-llm-gateway.internal" in n for n in wrong.notes)

    right = g.preflight([{"role": "user", "content": "x"}], provider="openai",
                        model="gpt-4.1-mini", pin=PIN, base_url="https://api.openai.com/v1")
    assert right.coverage == "measured"


def test_canonical_provider_names_reach_their_pin_row():
    """Hermes canonicalises names; the pin may know either form, and a canonical name that
    resolved to nothing used to be indistinguishable from 'nothing to worry about'."""
    for name, key in (("github-copilot", "copilot"), ("kimi-for-coding", "kimi-coding"),
                      ("kimi-coding-cn", "kimi-coding"), ("deep-infra", "deepinfra"),
                      ("deepinfra-ai", "deepinfra"), ("qwen-oauth", "alibaba"),
                      ("qwencloud", "alibaba"), ("dashscope-cn", "alibaba"),
                      ("nebius", "nebius-token-factory")):
        assert g.resolve(PIN, name).key == key, name
    assert g.resolve(PIN, "dashscope-cn").region_mismatch is True


def test_a_canonical_name_cannot_shadow_the_row_under_the_given_name():
    """Hermes maps the bare name 'openai' to 'openrouter'. Following that first would drop
    the openai row -- a false negative on the best-measured wall in the dataset."""
    assert g.resolve(PIN, "openai").key == "openai"
    assert g.resolve(PIN, "openai-api").key == "openai"


def test_the_pin_carries_a_checkable_receipt():
    """Provenance is self-asserted, so at least make it checkable: the dataset's hash and the
    builder's hash ride in the pin, and the pin's own hash is reported as loaded."""
    source = PIN["source"]
    assert len(source["dataset_sha256"]) == 64 and len(source["builder_sha256"]) == 64
    assert g.load_pin()["providers"]
    assert g.pin_digest() == hashlib.sha256(g.PIN_FILE.read_bytes()).hexdigest()
    assert g.pin_path().endswith("limits.pin.json")
