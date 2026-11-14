import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from opentelemetry.sdk.trace import TracerProvider

import tracelock
from tracelock.integration import init_keys
from tracelock.signing import load_public_key, public_key_hex
from tracelock.verify import verify_files
from tracelock.witness import Witness, make_server, serve_in_thread, server_url

ROOT = Path(__file__).resolve().parent.parent


def run_spans(tl, n=4):
    tracer = tl.tracer()
    with tracer.start_as_current_span("invoke_agent") as root:
        root.set_attribute("gen_ai.operation.name", "invoke_agent")
        for i in range(n):
            with tracer.start_as_current_span(f"chat {i}") as s:
                s.set_attribute("gen_ai.operation.name", "chat")
                s.set_attribute("gen_ai.input.messages", f"question {i}")
                s.set_attribute("gen_ai.output.messages", f"answer {i}")


def test_init_keys_creates_and_reuses(tmp_path):
    a = init_keys(tmp_path)
    assert all(p.exists() for p in (a.log_key, a.log_pub, a.agent_key, a.agent_pub))
    before = public_key_hex(load_public_key(a.log_pub)), public_key_hex(load_public_key(a.agent_pub))
    b = init_keys(tmp_path)  # second call must not rotate keys
    assert before == (public_key_hex(load_public_key(b.log_pub)), public_key_hex(load_public_key(b.agent_pub)))
    assert before[0] != before[1]


def test_setup_end_to_end_with_witness_passes_verifier(tmp_path):
    data = tmp_path / "data"
    keys = init_keys(data)  # the witness needs log.pub before it can start
    witness = Witness(tmp_path / "witness", load_public_key(keys.log_pub))
    server = make_server(witness)
    serve_in_thread(server)
    try:
        with tracelock.setup(data, witness_url=server_url(server), sth_interval=3,
                             provider=TracerProvider(), session_id="s1") as tl:
            run_spans(tl, 4)
            out = tl.export()
            assert tl.witness_errors == []
        res = verify_files(out.trace, out.log_pub, out.agent_pub,
                           [tmp_path / "witness" / "witness.pub"], out.witnessed_sths)
        assert res["overall"] == "PASS", res["checks"]
        assert res["events_checked"] == 5 + 1  # 5 spans + session_end
        assert res["unwitnessed_tail"]["events_in_tail"] == 0
    finally:
        server.shutdown(); server.server_close()


def test_without_witness_nothing_is_anchored(tmp_path):
    tl = tracelock.setup(tmp_path / "d", provider=TracerProvider())
    run_spans(tl, 2)
    out = tl.export()
    tl.close()
    assert out.witnessed_sths is None and out.trace.exists()


def test_end_session_and_close_are_idempotent_and_export_ends_the_session(tmp_path):
    tl = tracelock.setup(tmp_path / "d", provider=TracerProvider(), session_id="x")
    run_spans(tl, 2)
    tl.end_session(); tl.end_session()
    tl.export(); tl.close(); tl.close()
    lines = (tmp_path / "d" / "export" / "trace.jsonl").read_text().splitlines()
    assert sum('"name": "session_end"' in l or '"name":"session_end"' in l for l in lines) == 1


def test_setup_reuses_keys_and_ledger_across_runs(tmp_path):
    d = tmp_path / "d"
    tl1 = tracelock.setup(d, provider=TracerProvider(), session_id="one")
    run_spans(tl1, 2); tl1.close()
    tl2 = tracelock.setup(d, provider=TracerProvider(), session_id="two")
    assert tl2.ledger.size == 4  # 3 spans + session_end from the first run, appended to
    run_spans(tl2, 1); tl2.close()
    assert tl2.keys.log_pub.read_text() == tl1.keys.log_pub.read_text()


# --- packaging --------------------------------------------------------------------------------


def test_importing_tracelock_or_verify_never_imports_opentelemetry():
    code = ("import sys, tracelock, tracelock.verify, tracelock.report; "
            "bad = [m for m in sys.modules if m.startswith('opentelemetry')]; "
            "assert not bad, bad; print('ok')")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0 and "ok" in r.stdout, r.stderr


def test_lazy_exports_resolve_and_unknown_names_fail():
    assert tracelock.setup is not None and tracelock.init_keys is not None and tracelock.TraceLock is not None
    with pytest.raises(AttributeError):
        tracelock.does_not_exist


def test_pyproject_is_consistent_with_the_code():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text())
    proj = meta["project"]
    assert proj["version"] == tracelock.__version__
    for script, target in proj["scripts"].items():
        mod, func = target.split(":")
        assert callable(getattr(__import__(mod, fromlist=[func]), func)), script
    reqs = (ROOT / "requirements.txt").read_text().lower()
    for dep in proj["dependencies"]:
        name = dep.replace("<", ">").split(">")[0].split("=")[0].strip()
        assert name in reqs, f"{name} missing from requirements.txt"
    assert meta["tool"]["setuptools"]["packages"]["find"]["include"] == ["tracelock*"]


def test_quickstart_example_runs_and_is_rerunnable(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("quickstart", ROOT / "examples" / "quickstart.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    work = str(tmp_path / "q")
    assert mod.main(work) == 0
    assert mod.main(work) == 0  # second run reuses keys, ledger and the witness chain
    assert (tmp_path / "q" / "tracelock_data" / "export" / "trace.jsonl").exists()
