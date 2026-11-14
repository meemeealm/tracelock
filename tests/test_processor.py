"""Processor tests. FakeSpan mimics the attributes of opentelemetry's ReadableSpan;
the final test uses the real SDK and is skipped if it is not installed."""
from types import SimpleNamespace

import pytest

from tracelock.canonical import sha256_hex
from tracelock.ledger import SESSION_COUNT_ATTR, Ledger
from tracelock.merkle import leaf_hash, verify_inclusion
from tracelock.processor import (
    REDACTED, TraceLockSpanProcessor, redact_obj, redact_text, span_to_event,
)
from tracelock.signing import generate_private_key, verify


class FakeSpan:
    def __init__(self, name, attrs, trace_id=0xABC, span_id=0x1, parent=None, status="OK",
                 start=100, end=200):
        self.name = name
        self.attributes = attrs
        self.context = SimpleNamespace(trace_id=trace_id, span_id=span_id)
        self.parent = SimpleNamespace(span_id=parent) if parent is not None else None
        self.status = SimpleNamespace(status_code=SimpleNamespace(name=status))
        self.start_time, self.end_time = start, end


def make(tmp_path, interval=0):
    log, agent = generate_private_key(), generate_private_key()
    led = Ledger(tmp_path / "l.db", log, agent, sth_interval=interval)
    return led, TraceLockSpanProcessor(led, session_id="sess"), agent


def test_whitelist_excludes_unlisted_and_sensitive_attributes():
    span = FakeSpan("chat", {
        "gen_ai.operation.name": "chat", "gen_ai.request.model": "m",
        "gen_ai.usage.input_tokens": 12, "http.url": "https://x", "authorization": "Bearer abcdefgh12345",
        "gen_ai.input.messages": "hello",
    })
    ev, _ = span_to_event(span)
    assert ev["attributes"] == {
        "gen_ai.operation.name": "chat", "gen_ai.request.model": "m", "gen_ai.usage.input_tokens": 12,
    }
    assert "seq" not in ev


def test_attribute_name_drift_mapped_in_one_place():
    ev, _ = span_to_event(FakeSpan("c", {
        "gen_ai.usage.prompt_tokens": 7, "gen_ai.usage.completion_tokens": 9,
    }))
    assert ev["attributes"] == {"gen_ai.usage.input_tokens": 7, "gen_ai.usage.output_tokens": 9}
    ev, _ = span_to_event(FakeSpan("c", {  # new name wins over old name
        "gen_ai.usage.prompt_tokens": 1, "gen_ai.usage.input_tokens": 2,
    }))
    assert ev["attributes"]["gen_ai.usage.input_tokens"] == 2


def test_event_shape_ids_status_times():
    ev, _ = span_to_event(FakeSpan("s", {"gen_ai.operation.name": "chat"}, trace_id=0xAB,
                                   span_id=0xCD, parent=0xEF, status="ERROR", start=5, end=9))
    assert ev["trace_id"] == "00" * 15 + "ab" and ev["span_id"] == "00" * 7 + "cd"
    assert ev["parent_span_id"] == "00" * 7 + "ef"
    assert (ev["status"], ev["start_time_ns"], ev["end_time_ns"]) == ("ERROR", 5, 9)
    root_ev, _ = span_to_event(FakeSpan("r", {"gen_ai.operation.name": "chat"}))
    assert root_ev["parent_span_id"] is None
    assert root_ev["session_id"] == "default"


def test_floats_in_attributes_become_strings():
    ev, _ = span_to_event(FakeSpan("s", {"gen_ai.request.model": 1.5}))
    assert ev["attributes"]["gen_ai.request.model"] == "1.5"


def test_payload_hashed_and_returned_for_storage(tmp_path):
    led, proc, _ = make(tmp_path)
    proc.on_end(FakeSpan("c", {"gen_ai.operation.name": "chat",
                               "gen_ai.input.messages": "what is 2+2", "gen_ai.output.messages": "4"}))
    ev = led.get_event(0).event
    assert ev["payload_hashes"] == {"input_sha256": sha256_hex(b"what is 2+2"),
                                    "output_sha256": sha256_hex(b"4")}
    assert led.get_payload(ev["payload_hashes"]["input_sha256"]) == b"what is 2+2"
    assert "what is 2+2" not in led.get_event(0).leaf_data.decode()  # leaf has hashes only


def test_structured_payload_is_deterministic():
    a = span_to_event(FakeSpan("t", {"gen_ai.tool.call.arguments": {"b": 1, "a": [1, 2.5]}}))
    b = span_to_event(FakeSpan("t", {"gen_ai.tool.call.arguments": {"a": [1, 2.5], "b": 1}}))
    assert a[0]["payload_hashes"] == b[0]["payload_hashes"] and a[1] == b[1]


def test_redaction_before_hashing_and_storage(tmp_path, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "envsecret-123456")
    led, proc, _ = make(tmp_path)
    proc.on_end(FakeSpan("c", {
        "gen_ai.operation.name": "chat",
        "gen_ai.input.messages": "call with Authorization: Bearer gsk_abcdefghijklmnop1234 and envsecret-123456",
        "gen_ai.output.messages": {"headers": {"Authorization": "Bearer zzzzzzzzzzzz"}, "api_key": "k", "ok": "fine"},
    }))
    ev = led.get_event(0).event
    for field in ("input_sha256", "output_sha256"):
        stored = led.get_payload(ev["payload_hashes"][field]).decode()
        for secret in ("gsk_abcdefghijklmnop1234", "envsecret-123456", "zzzzzzzzzzzz"):
            assert secret not in stored
        assert REDACTED in stored
    assert "fine" in led.get_payload(ev["payload_hashes"]["output_sha256"]).decode()


def test_redaction_helpers():
    assert redact_text("key sk-abcdefghijklmnopqrstu done") == f"key {REDACTED} done"
    assert redact_text('{"api_key": "abc123"}') == '{"api_key": "' + REDACTED + '"}'
    assert redact_text("nothing sensitive here") == "nothing sensitive here"
    assert redact_obj({"X-Api-Key": "v", "n": [{"password": "p", "t": "Bearer abcdefgh1234"}]}) == {
        "X-Api-Key": REDACTED, "n": [{"password": REDACTED, "t": REDACTED}]}


def test_non_genai_spans_are_ignored(tmp_path):
    led, proc, _ = make(tmp_path)
    proc.on_end(FakeSpan("GET /", {"http.method": "GET"}))
    assert led.size == 0
    proc.on_end(FakeSpan("chat", {"gen_ai.operation.name": "chat"}))
    assert led.size == 1


def test_child_before_parent_ordered_by_seq_not_time(tmp_path):
    led, proc, _ = make(tmp_path)
    proc.on_end(FakeSpan("child", {"gen_ai.operation.name": "execute_tool"}, span_id=2, parent=1, start=150, end=160))
    proc.on_end(FakeSpan("parent", {"gen_ai.operation.name": "invoke_agent"}, span_id=1, start=100, end=200))
    names = [led.get_event(i).event["name"] for i in range(2)]
    assert names == ["child", "parent"]  # seq follows end order; parent starts earlier


def test_checkpoint_dummy_span_inclusion_proof_verifies(tmp_path):
    led, proc, agent = make(tmp_path)
    for i in range(5):
        proc.on_end(FakeSpan(f"s{i}", {"gen_ai.operation.name": "chat"}, span_id=i + 1))
    se = led.get_event(3)
    assert verify_inclusion(leaf_hash(se.leaf_data), 3, led.size, led.inclusion_proof(3), led.root)
    assert verify(agent.public_key(), se.leaf_hash, se.signature)


def test_end_session_via_processor(tmp_path):
    led, proc, _ = make(tmp_path)
    for i in range(3):
        proc.on_end(FakeSpan("s", {"gen_ai.operation.name": "chat"}, span_id=i + 1))
    proc.end_session()
    assert led.get_event(3).event["attributes"][SESSION_COUNT_ATTR] == 3
    assert led.latest_sth().tree_size == 4


def test_real_otel_sdk_end_to_end(tmp_path):
    pytest.importorskip("opentelemetry.sdk.trace.export")
    from opentelemetry.sdk.trace import TracerProvider

    led, proc, agent = make(tmp_path)
    provider = TracerProvider()
    provider.add_span_processor(proc)
    tracer = provider.get_tracer("test")
    with tracer.start_as_current_span("invoke_agent") as parent:
        parent.set_attribute("gen_ai.operation.name", "invoke_agent")
        with tracer.start_as_current_span("chat") as child:
            child.set_attribute("gen_ai.operation.name", "chat")
            child.set_attribute("gen_ai.request.model", "some-model")
            child.set_attribute("gen_ai.usage.input_tokens", 5)
            child.set_attribute("gen_ai.input.messages", "hi")
    with tracer.start_as_current_span("http"):
        pass  # no gen_ai attributes: ignored
    assert led.size == 2
    e0, e1 = led.get_event(0).event, led.get_event(1).event
    assert (e0["name"], e1["name"]) == ("chat", "invoke_agent")  # child ends first
    assert e0["parent_span_id"] == e1["span_id"] and e1["parent_span_id"] is None
    assert e0["attributes"]["gen_ai.usage.input_tokens"] == 5
    for i in range(2):
        se = led.get_event(i)
        assert verify_inclusion(se.leaf_hash, i, 2, led.inclusion_proof(i), led.root)
        assert verify(agent.public_key(), se.leaf_hash, se.signature)
