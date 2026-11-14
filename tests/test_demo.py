import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from opentelemetry.sdk.trace import TracerProvider

from demo.agent_groq import call_with_backoff, is_retryable, run_agent
from demo.agent_scripted import produce_artifacts, run_session
from demo.fixtures_io import RecordingProcessor, replay_fixture
from demo.tools import Toolbox
from tracelock.verify import verify_files

FIXTURE = Path(__file__).parent.parent / "demo" / "fixtures" / "scripted_session.json"


def record(session_fn):
    rec = RecordingProcessor()
    provider = TracerProvider()
    provider.add_span_processor(rec)
    session_fn(provider.get_tracer("t"))
    return rec.records


def signature(records):
    """Everything deterministic about a run (ids and times are not)."""
    return [(r["name"], json.dumps(r["attributes"], sort_keys=True)) for r in sorted(records, key=lambda r: r["start_time_ns"])]


# --- tools --------------------------------------------------------------------------------


def test_tools_have_no_side_effects_beyond_the_outbox():
    t = Toolbox()
    assert "ship the audit report" in t.read_file("notes.txt")
    assert t.read_file("../../etc/passwd").startswith("error")
    assert t.calculator("12 * (3 + 4)") == "84"
    assert t.calculator("2 ** 1000").startswith("error")  # exponent guard
    for evil in ("__import__('os').system('id')", "open('x')", "1/0", "(1"):
        assert t.calculator(evil).startswith("error")
    out = json.loads(t.send_email_stub("a@b.c", "hi", "body"))
    assert out["status"] == "queued" and t.outbox == [{"to": "a@b.c", "subject": "hi", "body": "body"}]
    assert t.call("nope", {}).startswith("error") and t.call("calculator", {"bad": 1}).startswith("error")


# --- scripted agent --------------------------------------------------------------------------


def test_scripted_agent_is_deterministic_for_a_seed():
    a = record(lambda tr: run_session(tr, seed=7))
    b = record(lambda tr: run_session(tr, seed=7))
    c = record(lambda tr: run_session(tr, seed=8))
    assert signature(a) == signature(b)
    assert signature(a) != signature(c)


def test_scripted_agent_span_count_tools_and_shape():
    for seed in range(1, 12):
        recs = record(lambda tr: run_session(tr, seed=seed))
        assert 10 <= len(recs) <= 20
        tools = {r["attributes"].get("gen_ai.tool.name") for r in recs} - {None}
        assert "send_email_stub" in tools and tools <= {"read_file", "send_email_stub", "calculator"}
        assert sum(1 for r in recs if r["parent_span_id"] is None) == 1  # one root span


def test_scripted_pipeline_is_verifiable_for_several_seeds_and_intervals(tmp_path):
    for seed, interval in ((1, 1), (2, 3), (3, 50)):
        art = produce_artifacts(tmp_path / f"a{seed}", seed=seed, sth_interval=interval)
        assert art.hook_errors == []
        res = verify_files(**art.verify_args())
        assert res["overall"] == "PASS", (seed, interval, res["checks"])


# --- fixtures ----------------------------------------------------------------------------------


def test_recorded_fixture_replays_offline_and_verifies(tmp_path):
    spans = len(json.loads(FIXTURE.read_text())["spans"])
    art = produce_artifacts(tmp_path, session_fn=lambda tr: replay_fixture(FIXTURE, tr))
    assert art.n_events == spans + 1  # + session_end
    assert verify_files(**art.verify_args())["overall"] == "PASS"
    original = json.loads(FIXTURE.read_text())["spans"]
    replayed = record(lambda tr: replay_fixture(FIXTURE, tr))
    assert signature(replayed) == signature(original)


# --- groq agent logic against a fake client (no network) --------------------------------------------


def resp(content=None, calls=(), usage=(11, 5)):
    tcs = [SimpleNamespace(id=cid, function=SimpleNamespace(name=n, arguments=a)) for cid, n, a in calls]
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content, tool_calls=tcs or None))],
        usage=SimpleNamespace(prompt_tokens=usage[0], completion_tokens=usage[1]))


class FakeClient:
    def __init__(self, items):
        self.items, self.calls = list(items), []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kw):
        self.calls.append(json.loads(json.dumps(kw["messages"])))
        item = self.items.pop(0) if len(self.items) > 1 else self.items[0]
        if isinstance(item, Exception):
            raise item
        return item


class HttpError(Exception):
    def __init__(self, status):
        super().__init__(f"http {status}")
        self.status_code = status


def test_retry_policy_and_exponential_backoff():
    assert [is_retryable(HttpError(s)) for s in (429, 500, 503, 400, 401, 404)] == [True, True, True, False, False, False]
    assert not is_retryable(ValueError("x"))
    delays, attempts = [], []

    def flaky():
        attempts.append(1)
        if len(attempts) < 4:
            raise HttpError(429 if len(attempts) % 2 else 503)
        return "ok"

    assert call_with_backoff(flaky, base_delay=1.0, sleep=delays.append, jitter=lambda: 0.0) == "ok"
    assert delays == [1.0, 2.0, 4.0]
    with pytest.raises(HttpError):  # non-retryable: raised at once
        call_with_backoff(lambda: (_ for _ in ()).throw(HttpError(400)), sleep=delays.append)
    n = []
    with pytest.raises(HttpError):  # gives up after max_retries
        call_with_backoff(lambda: n.append(1) or (_ for _ in ()).throw(HttpError(500)), max_retries=2, sleep=lambda s: None)
    assert len(n) == 3


def test_agent_loop_tool_call_then_answer(tmp_path):
    client = FakeClient([
        resp(None, [("call_1", "read_file", '{"path": "notes.txt"}')]),
        resp("The report ships Friday."),
    ])
    answers = []
    art = produce_artifacts(tmp_path, session_id="g", session_fn=lambda tr: answers.append(
        run_agent(client, "some-model", "What is in notes.txt?", tr)))
    assert answers == ["The report ships Friday."]
    tool_msg = client.calls[1][-1]
    assert tool_msg["role"] == "tool" and tool_msg["tool_call_id"] == "call_1" and "audit report" in tool_msg["content"]
    res = verify_files(**art.verify_args())
    assert res["overall"] == "PASS"
    names = [e["name"] for e in res["events"]]
    assert sorted(names) == sorted(["invoke_agent", "chat some-model", "chat some-model",
                                    "execute_tool read_file", "session_end"])
    trace = [json.loads(l)["event"] for l in art.trace.read_text().splitlines()]
    chat = next(e for e in trace if e["name"].startswith("chat"))
    assert chat["attributes"]["gen_ai.usage.input_tokens"] == 11


def test_agent_respects_max_steps_and_bad_tool_arguments():
    client = FakeClient([resp(None, [("c", "calculator", "{not json")])])  # repeats forever
    recs = record(lambda tr: run_agent(client, "m", "loop", tr, max_steps=10))
    assert len(client.calls) == 10
    results = [r["attributes"]["gen_ai.tool.call.result"] for r in recs if "gen_ai.tool.call.result" in r["attributes"]]
    assert len(results) == 10 and all(x == "error: invalid JSON arguments" for x in results)


def test_agent_retries_429_inside_the_loop():
    client = FakeClient([HttpError(429), HttpError(503), resp("fine")])
    sleeps = []
    out = []
    record(lambda tr: out.append(run_agent(client, "m", "hi", tr, sleep=sleeps.append)))
    assert out == ["fine"] and len(sleeps) == 2 and sleeps[1] > sleeps[0]


def test_api_key_never_reaches_trace_or_ledger(tmp_path, monkeypatch):
    key = "gsk_THISISAFAKEKEYFORTESTING123456"
    monkeypatch.setenv("GROQ_API_KEY", key)
    client = FakeClient([
        resp(None, [("c1", "send_email_stub", json.dumps({"to": "a@b.c", "subject": "s", "body": f"Authorization: Bearer {key}"}))]),
        resp(f"done, key was {key}"),
    ])
    art = produce_artifacts(tmp_path, session_fn=lambda tr: run_agent(
        client, "m", f"my key is {key}, please use header 'Authorization: Bearer {key}'", tr))
    blob = art.trace.read_text() + "".join(p.read_text(errors="ignore") for p in tmp_path.rglob("*.json*"))
    import sqlite3
    db = sqlite3.connect(art.ledger_db)
    blob += repr(db.execute("SELECT * FROM events").fetchall()) + repr(db.execute("SELECT * FROM payloads").fetchall())
    assert key not in blob and "THISISAFAKEKEY" not in blob
    assert "[REDACTED]" in blob
    assert verify_files(**art.verify_args())["overall"] == "PASS"


def test_run_all_demo_uses_a_separate_witness_process(tmp_path):
    from demo.run_all import main as run_all_main
    out = tmp_path / "demo_out"
    assert run_all_main(["--out-dir", str(out)]) == 0
    for name in ("trace.jsonl", "witnessed_sths.json", "verification.json", "report.html", "ledger.db"):
        assert (out / name).exists(), name
    result = json.loads((out / "verification.json").read_text())
    assert result["overall"] == "PASS" and len(json.loads((out / "witnessed_sths.json").read_text())) >= 2
    assert (out / "witness_data" / "witness.key").exists()  # the witness process wrote its own key
    assert "banner pass" in (out / "report.html").read_text(encoding="utf-8")
    assert run_all_main(["--out-dir", str(out)]) == 0  # re-runnable: wipes its own previous output
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "precious.txt").write_text("x")
    with pytest.raises(SystemExit):  # refuses to wipe a directory it did not create
        run_all_main(["--out-dir", str(tmp_path / "other")])
    assert (tmp_path / "other" / "precious.txt").exists()


# --- provider selection (Groq / OpenAI) ----------------------------------------------------------


def test_resolve_provider_groq_openai_and_errors():
    from demo.agent_groq import GROQ_BASE_URL, ConfigError, resolve_provider
    g = resolve_provider("groq", {"GROQ_API_KEY": "k1", "GROQ_MODEL": "m1", "OPENAI_API_KEY": "ignored"})
    assert (g.name, g.base_url, g.api_key, g.model) == ("groq", GROQ_BASE_URL, "k1", "m1")
    o = resolve_provider("openai", {"OPENAI_API_KEY": "k2", "OPENAI_MODEL": "m2"})
    assert (o.base_url, o.api_key, o.model) == (None, "k2", "m2")  # None = SDK default endpoint
    custom = resolve_provider("openai", {"OPENAI_API_KEY": "k", "OPENAI_MODEL": "m", "OPENAI_BASE_URL": "http://proxy/v1"})
    assert custom.base_url == "http://proxy/v1"
    try:
        resolve_provider("openai", {"GROQ_API_KEY": "only-groq"})
        raise AssertionError("expected ConfigError")
    except ConfigError as exc:
        assert "OPENAI_API_KEY" in str(exc) and "OPENAI_MODEL" in str(exc)
    with pytest.raises(ConfigError):
        resolve_provider("nope", {})
    assert "k2" not in repr(o)  # the key never appears in reprs or tracebacks


def test_main_reports_missing_config_without_needing_openai_installed():
    from demo.agent_groq import main as llm_main
    assert llm_main(["--provider", "openai"], env={}) == 2
    assert llm_main(["--provider", "groq"], env={"OPENAI_API_KEY": "x", "OPENAI_MODEL": "y"}) == 2
    assert llm_main([], env={"LLM_PROVIDER": "openai"}) == 2  # provider taken from LLM_PROVIDER


def test_openai_style_keys_never_reach_trace_or_ledger(tmp_path, monkeypatch):
    key = "sk-proj-THISISAFAKEOPENAIKEY1234567890abcdef"
    monkeypatch.setenv("OPENAI_API_KEY", key)
    client = FakeClient([
        resp(None, [("c1", "send_email_stub", json.dumps({"to": "a@b.c", "subject": "s", "body": f"OPENAI_API_KEY={key}"}))]),
        resp(f"done, key was {key}"),
    ])
    art = produce_artifacts(tmp_path, session_fn=lambda tr: run_agent(client, "gpt-test", f"use {key}", tr))
    import sqlite3
    db = sqlite3.connect(art.ledger_db)
    blob = art.trace.read_text() + repr(db.execute("SELECT * FROM events").fetchall()) \
        + repr(db.execute("SELECT * FROM payloads").fetchall())
    assert key not in blob and "THISISAFAKEOPENAIKEY" not in blob and "[REDACTED]" in blob
    assert verify_files(**art.verify_args())["overall"] == "PASS"
