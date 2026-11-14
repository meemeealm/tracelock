"""Deterministic offline agent: 3 mock tools, seeded, no network.

Every decision comes from ``random.Random(seed)``, so the sequence of tool calls
and payloads is identical for a given seed (span ids and timestamps are not).
``produce_artifacts`` wires the whole pipeline (agent -> ledger -> witness ->
export) and is used by the tests, the benchmark and the attack scripts.
"""
from __future__ import annotations

import json
import random
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from opentelemetry.sdk.trace import TracerProvider

from tracelock.ledger import Ledger
from tracelock.processor import TraceLockSpanProcessor
from tracelock.signing import (
    generate_private_key, load_private_key, save_private_key, save_public_key,
)
from tracelock.witness import Witness, WitnessClient, make_server, serve_in_thread, server_url

from .tools import Toolbox

MODEL = "scripted-model-1"
DEFAULT_SEED = 1234


def run_session(tracer: Any, seed: int = DEFAULT_SEED, toolbox: Toolbox | None = None) -> dict[str, Any]:
    """Run one scripted session (about 10-16 spans). Returns a small summary."""
    rng = random.Random(seed)
    tools = toolbox or Toolbox()
    n_steps = rng.randint(4, 7)
    messages: list[dict[str, str]] = [
        {"role": "system", "content": "You are a scripted demo agent."},
        {"role": "user", "content": "Summarise the files and do some sums, then email the auditor."},
    ]
    names = ["read_file", "calculator", "send_email_stub"]
    spans = 0
    with tracer.start_as_current_span("invoke_agent") as root:
        root.set_attribute("gen_ai.operation.name", "invoke_agent")
        root.set_attribute("gen_ai.request.model", MODEL)
        spans += 1
        for step in range(n_steps):
            # The last step always sends the email so every tool is exercised.
            tool = "send_email_stub" if step == n_steps - 1 else rng.choice(names[:2])
            if tool == "read_file":
                args = {"path": rng.choice(sorted(tools.files))}
            elif tool == "calculator":
                args = {"expression": f"{rng.randint(2, 99)} {rng.choice('+-*')} {rng.randint(2, 99)}"}
            else:
                args = {"to": "auditor@example.com", "subject": f"update {step}",
                        "body": messages[-1]["content"][:60]}
            call_id = f"call_{seed}_{step}"
            decision = json.dumps({"tool_calls": [{"id": call_id, "name": tool, "arguments": args}]},
                                  sort_keys=True)
            prompt = json.dumps(messages)
            with tracer.start_as_current_span(f"chat {MODEL}") as chat:
                chat.set_attribute("gen_ai.operation.name", "chat")
                chat.set_attribute("gen_ai.request.model", MODEL)
                chat.set_attribute("gen_ai.usage.input_tokens", len(prompt) // 4)
                chat.set_attribute("gen_ai.usage.output_tokens", len(decision) // 4)
                chat.set_attribute("gen_ai.input.messages", prompt)
                chat.set_attribute("gen_ai.output.messages", decision)
            with tracer.start_as_current_span(f"execute_tool {tool}") as ts:
                result = tools.call(tool, args)
                ts.set_attribute("gen_ai.operation.name", "execute_tool")
                ts.set_attribute("gen_ai.tool.name", tool)
                ts.set_attribute("gen_ai.tool.call.id", call_id)
                ts.set_attribute("gen_ai.tool.call.arguments", json.dumps(args, sort_keys=True))
                ts.set_attribute("gen_ai.tool.call.result", result)
            messages.append({"role": "tool", "content": result})
            spans += 2
        answer = f"Done after {n_steps} tool calls."
        prompt = json.dumps(messages)
        with tracer.start_as_current_span(f"chat {MODEL}") as chat:
            chat.set_attribute("gen_ai.operation.name", "chat")
            chat.set_attribute("gen_ai.request.model", MODEL)
            chat.set_attribute("gen_ai.usage.input_tokens", len(prompt) // 4)
            chat.set_attribute("gen_ai.usage.output_tokens", len(answer) // 4)
            chat.set_attribute("gen_ai.input.messages", prompt)
            chat.set_attribute("gen_ai.output.messages", answer)
        spans += 1
    return {"spans": spans, "answer": answer, "emails": len(tools.outbox)}


@dataclass
class Artifacts:
    out_dir: Path
    trace: Path
    ledger_db: Path
    log_pub: Path
    agent_pub: Path
    witness_pubs: list[Path]
    witnessed_sths: Path
    n_events: int
    hook_errors: list[str] = field(default_factory=list)

    def verify_args(self) -> dict[str, Any]:
        return dict(trace=self.trace, log_pubkey=self.log_pub, agent_pubkey=self.agent_pub,
                    witness_pubkeys=self.witness_pubs, witnessed_sths=self.witnessed_sths)


def _load_or_create(path: Path) -> Any:
    if path.exists():
        return load_private_key(path)
    key = generate_private_key()
    save_private_key(key, path)
    return key


def produce_artifacts(
    out_dir: str | Path,
    seed: int = DEFAULT_SEED,
    sth_interval: int = 5,
    session_id: str = "demo-session",
    session_fn: Callable[[Any], Any] | None = None,
    end_session: bool = True,
    extra_processors: tuple[Any, ...] = (),
    witness_url: str | None = None,
    witness_dir: str | Path | None = None,
) -> Artifacts:
    """agent -> TraceLock processor -> ledger -> witness (HTTP) -> exported artifacts.

    ``end_session=False`` leaves an unwitnessed tail (used by the attack scripts).
    By default the witness runs in-process on a loopback port with its own key and
    data dir: a demo of the protocol, not real independence. Pass ``witness_url`` and
    ``witness_dir`` to use an already running witness process instead (see demo.run_all).
    Existing key files in ``out_dir/keys`` are reused, so keys can be created first.
    """
    out = Path(out_dir)
    keys = out / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    log_key, agent_key = _load_or_create(keys / "log.key"), _load_or_create(keys / "agent.key")
    save_public_key(log_key.public_key(), keys / "log.pub")
    save_public_key(agent_key.public_key(), keys / "agent.pub")

    external = witness_url is not None
    if external:
        witness_dir = Path(witness_dir or out / "witness_data")
        server = None
    else:
        witness_dir = out / "witness_data"
        witness = Witness(witness_dir, log_key.public_key())
        server = make_server(witness)
        serve_in_thread(server)
        witness_url = server_url(server)
    ledger = Ledger(out / "ledger.db", log_key, agent_key, sth_interval=sth_interval)
    try:
        ledger.sth_hook = WitnessClient(witness_url, ledger.consistency_proof).submit
        provider = TracerProvider()
        provider.add_span_processor(proc := TraceLockSpanProcessor(ledger, session_id))
        for extra in extra_processors:
            provider.add_span_processor(extra)
        tracer = provider.get_tracer("tracelock.demo")
        (session_fn or (lambda t: run_session(t, seed)))(tracer)
        if end_session:
            proc.end_session()
        provider.shutdown()
        n = ledger.export_trace(out / "trace.jsonl")
        if external:
            with urllib.request.urlopen(witness_url + "/sths", timeout=5) as resp:
                (out / "witnessed_sths.json").write_bytes(resp.read())
        else:
            witness.export(out / "witnessed_sths.json")
        hook_errors = list(ledger.hook_errors)
    finally:
        ledger.close()
        if server is not None:
            server.shutdown()
            server.server_close()
    return Artifacts(out, out / "trace.jsonl", out / "ledger.db", keys / "log.pub", keys / "agent.pub",
                     [witness_dir / "witness.pub"], out / "witnessed_sths.json", n, hook_errors)
