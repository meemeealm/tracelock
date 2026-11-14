"""Runnable quickstart: record a tiny fake agent run, have it witnessed, then verify it.

    python examples/quickstart.py [work_dir]

No network and no API key. The "agent" below is a stand-in that emits gen_ai.* spans; replace
`fake_agent` with your real agent code (anything that emits OpenTelemetry spans through the
tracer). In real use the witness runs on a DIFFERENT machine under someone else's control;
here it runs inside this script on localhost purely so the example is self-contained.
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    import tracelock
except ModuleNotFoundError:  # running from a fresh checkout without `pip install -e .`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import tracelock
from tracelock.signing import load_public_key
from tracelock.verify import verify_files
from tracelock.witness import Witness, make_server, serve_in_thread, server_url


def fake_agent(tracer) -> None:
    """Stand-in for your agent: one root span, two model calls, one tool call."""
    with tracer.start_as_current_span("invoke_agent") as root:
        root.set_attribute("gen_ai.operation.name", "invoke_agent")
        with tracer.start_as_current_span("chat demo-model") as s:
            s.set_attribute("gen_ai.operation.name", "chat")
            s.set_attribute("gen_ai.request.model", "demo-model")
            s.set_attribute("gen_ai.input.messages", "What is 6 * 7?")
            s.set_attribute("gen_ai.output.messages", "call calculator(6*7)")
        with tracer.start_as_current_span("execute_tool calculator") as s:
            s.set_attribute("gen_ai.operation.name", "execute_tool")
            s.set_attribute("gen_ai.tool.name", "calculator")
            s.set_attribute("gen_ai.tool.call.arguments", '{"expression": "6 * 7"}')
            s.set_attribute("gen_ai.tool.call.result", "42")
        with tracer.start_as_current_span("chat demo-model") as s:
            s.set_attribute("gen_ai.operation.name", "chat")
            s.set_attribute("gen_ai.request.model", "demo-model")
            s.set_attribute("gen_ai.input.messages", "tool result: 42")
            s.set_attribute("gen_ai.output.messages", "6 * 7 = 42")


def main(work_dir: str = "quickstart_out") -> int:
    work = Path(work_dir)
    data = work / "tracelock_data"

    keys = tracelock.init_keys(data)  # 1) keys (reused on later runs); the witness needs log.pub
    witness = Witness(work / "witness_data", load_public_key(keys.log_pub))  # 2) witness (demo only)
    server = make_server(witness)
    serve_in_thread(server)
    try:
        # 3) one call wires the ledger, span processor and witness client
        with tracelock.setup(data, witness_url=server_url(server), sth_interval=3) as tl:
            fake_agent(tl.tracer())  # 4) your agent runs
            out = tl.export()        # 5) ends the session, writes trace.jsonl, fetches witnessed STHs
            witness_errors = tl.witness_errors
    finally:
        server.shutdown()
        server.server_close()

    # 6) what an auditor would do, using only the exported files and public keys
    result = verify_files(out.trace, out.log_pub, out.agent_pub,
                          [work / "witness_data" / "witness.pub"], out.witnessed_sths)
    print(f"verifier: {result['overall']} ({result['events_checked']} events)")
    for name, check in result["checks"].items():
        print(f"  {check['status']:4} {name}: {check['detail']}")
    print(f"witness errors: {witness_errors or 'none'}")
    print(f"files for an auditor are in: {out.trace.parent}")
    return 0 if result["overall"] == "PASS" and not witness_errors else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:2]))
