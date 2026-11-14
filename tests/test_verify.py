import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from demo.agent_scripted import produce_artifacts
from tracelock import verify as V
from tracelock.canonical import canonical_json
from tracelock.ledger import SESSION_COUNT_ATTR, SESSION_END_NAME, Ledger
from tracelock.merkle import MerkleTree, leaf_hash, verify_consistency, verify_inclusion
from tracelock.signing import generate_private_key, save_public_key
from tracelock.witness import Witness

VERIFY_PY = Path(V.__file__)


def build(tmp_path, **kw):
    return produce_artifacts(tmp_path / "art", **kw)


def run(art, trace=None, sths=None, witness_pubs=None):
    a = art.verify_args()
    return V.verify_files(trace or a["trace"], a["log_pubkey"], a["agent_pubkey"],
                          witness_pubs or a["witness_pubkeys"], sths or a["witnessed_sths"])


def read_lines(path):
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines()]


def write_lines(path, lines):
    Path(path).write_text("".join(json.dumps(l, sort_keys=True, ensure_ascii=False) + "\n" for l in lines),
                          encoding="utf-8")
    return path


def statuses(res):
    return {k: v["status"] for k, v in res["checks"].items()}


# --- clean run (Stage 2 checkpoint) -------------------------------------------------


def test_clean_end_to_end_run_passes(tmp_path):
    art = build(tmp_path)
    assert art.hook_errors == [] and 10 <= art.n_events <= 20
    res = run(art)
    assert res["overall"] == "PASS", res["checks"]
    assert set(statuses(res).values()) == {"PASS"}
    assert res["first_broken_seq_range"] is None
    assert res["unwitnessed_tail"]["events_in_tail"] == 0  # session end witnessed the head
    assert all(e["ok"] for e in res["events"]) and len(res["events"]) == art.n_events
    assert all(s["valid"] and s["root_matches_trace"] for s in res["witnessed_sths"])
    assert res["checks"]["payload_hashes"]["verified"] > 0


def test_cli_exit_codes_and_json_output(tmp_path):
    art = build(tmp_path)
    a = art.verify_args()
    argv = ["--trace", str(a["trace"]), "--log-pubkey", str(a["log_pubkey"]),
            "--agent-pubkey", str(a["agent_pubkey"]), "--witness-pubkey", str(a["witness_pubkeys"][0]),
            "--witnessed-sths", str(a["witnessed_sths"]), "--out", str(tmp_path / "r.json")]
    assert V.main(argv) == 0
    assert json.loads((tmp_path / "r.json").read_text())["overall"] == "PASS"
    lines = read_lines(art.trace)
    del lines[4]
    bad = write_lines(tmp_path / "bad.jsonl", lines)
    argv[1] = str(bad)
    assert V.main(argv) == 1
    argv[1] = str(tmp_path / "missing.jsonl")
    assert V.main(argv) == 2


def test_runs_as_a_standalone_script_without_the_package(tmp_path):
    art = build(tmp_path)
    a = art.verify_args()
    cmd = [sys.executable, "-I", str(VERIFY_PY), "--trace", str(a["trace"]), "--log-pubkey", str(a["log_pubkey"]),
           "--agent-pubkey", str(a["agent_pubkey"]), "--witness-pubkey", str(a["witness_pubkeys"][0]),
           "--witnessed-sths", str(a["witnessed_sths"])]
    ok = subprocess.run(cmd, capture_output=True, text=True, cwd=tmp_path)
    assert ok.returncode == 0 and json.loads(ok.stdout)["overall"] == "PASS"
    lines = read_lines(art.trace)
    lines[3]["event"]["name"] = "edited"
    cmd[4] = str(write_lines(tmp_path / "t2.jsonl", lines))  # the value after --trace
    bad = subprocess.run(cmd, capture_output=True, text=True, cwd=tmp_path)
    assert bad.returncode == 1 and json.loads(bad.stdout)["overall"] == "FAIL"


def test_verifier_imports_only_stdlib_and_cryptography():
    tree = ast.parse(VERIFY_PY.read_text())
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative import"
            mods.add(node.module.split(".")[0])
    assert "tracelock" not in mods
    assert all(m in sys.stdlib_module_names or m == "cryptography" for m in mods), mods


# --- cross-check of verify.py's own RFC 6962 copy against merkle.py -----------------------


def test_verify_copy_agrees_with_merkle_module():
    data = [f"x{i}".encode() for i in range(32)]
    t = MerkleTree()
    acc = V.RootAccumulator()
    for d in data:
        t.append(d)
        acc.append(V.leaf_hash(d))
        assert acc.root() == t.root()
        assert V.leaf_hash(d) == leaf_hash(d)
    assert V.EMPTY_ROOT == MerkleTree().root() and V.RootAccumulator().root() == V.EMPTY_ROOT
    assert V.node_hash(b"a" * 32, b"b" * 32) == __import__("tracelock.merkle", fromlist=["x"]).node_hash(b"a" * 32, b"b" * 32)

    def flip(p):
        return bytes([p[0] ^ 1]) + p[1:]

    for size in range(1, 33):
        root = t.root_at(size)
        for i in range(size):
            proof = t.inclusion_proof(i, size)
            cases = [(proof, root)] + [([*proof[:j], flip(proof[j]), *proof[j + 1:]], root) for j in range(len(proof))]
            cases += [(proof[:-1], root), (proof, flip(root))]
            for pr, rt in cases:
                lh = leaf_hash(data[i])
                assert V.verify_inclusion(lh, i, size, pr, rt) == verify_inclusion(lh, i, size, pr, rt)
    for new in range(0, 33):
        for old in range(0, new + 1):
            proof = t.consistency_proof(old, new)
            o, n = t.root_at(old), t.root_at(new)
            cases = [(o, n, proof), (o, flip(n), proof), (flip(o), n, proof), (o, n, proof[:-1] if proof else [b"\0" * 32])]
            cases += [(o, n, [*proof[:j], flip(proof[j]), *proof[j + 1:]]) for j in range(len(proof))]
            for oo, nn, pr in cases:
                assert V.verify_consistency(old, new, oo, nn, pr) == verify_consistency(old, new, oo, nn, pr)
    assert V.verify_consistency(3, 9, t.root_at(3), t.root_at(9), t.consistency_proof(3, 9))


def test_verify_canonical_json_matches_tracelock_canonical():
    for obj in ({"b": 1, "a": [None, True, "é✓"]}, {"t": 1731234567890123456, "n": {"z": [], "y": {}}}, {}):
        assert V.canonical_json(obj) == canonical_json(obj)
    with pytest.raises(ValueError):
        V.canonical_json({"f": 1.5})


# --- tamper detection (full scenarios come in Stage 3) -------------------------------------


def test_edited_event_detected(tmp_path):
    art = build(tmp_path)
    lines = read_lines(art.trace)
    lines[6]["event"]["attributes"]["gen_ai.usage.input_tokens"] = 99999
    lines[6]["event"]["name"] = "edited"
    res = run(art, write_lines(tmp_path / "t.jsonl", lines))
    st = statuses(res)
    assert res["overall"] == "FAIL" and st["event_signatures"] == "FAIL" and st["merkle_root_vs_witnessed_sths"] == "FAIL"
    assert st["seq_continuity"] == "PASS"
    assert res["checks"]["event_signatures"]["ranges"] == [[6, 6]]
    lo, hi = res["first_broken_seq_range"]
    assert lo <= 6 <= hi and lo >= 5  # narrowed to between the last good checkpoint and the bad one
    assert not res["events"][6]["ok"]


def test_deleted_mid_event_detected(tmp_path):
    art = build(tmp_path)
    lines = read_lines(art.trace)
    del lines[7]
    res = run(art, write_lines(tmp_path / "t.jsonl", lines))
    st = statuses(res)
    assert st["seq_continuity"] == "FAIL" and st["merkle_root_vs_witnessed_sths"] == "FAIL"
    assert st["event_signatures"] == "PASS"  # every remaining event is individually authentic
    assert res["checks"]["seq_continuity"]["ranges"] == [[7, 7]]
    assert st["session_end_counts"] == "FAIL"  # the committed count no longer matches either


def test_duplicate_and_reordered_events_detected(tmp_path):
    art = build(tmp_path)
    lines = read_lines(art.trace)
    dup = lines[:5] + [lines[4]] + lines[5:]
    assert statuses(run(art, write_lines(tmp_path / "d.jsonl", dup)))["seq_continuity"] == "FAIL"
    swapped = list(lines)
    swapped[3], swapped[4] = swapped[4], swapped[3]
    r = run(art, write_lines(tmp_path / "s.jsonl", swapped))
    assert statuses(r)["seq_continuity"] == "FAIL" and statuses(r)["merkle_root_vs_witnessed_sths"] == "FAIL"


def test_truncation_before_last_witnessed_sth_detected(tmp_path):
    art = build(tmp_path)
    lines = read_lines(art.trace)[:12]
    res = run(art, write_lines(tmp_path / "t.jsonl", lines))
    assert res["overall"] == "FAIL" and statuses(res)["merkle_root_vs_witnessed_sths"] == "FAIL"
    assert statuses(res)["seq_continuity"] == "PASS"  # nothing looks wrong inside what is left
    assert res["first_broken_seq_range"][0] == 12


def test_truncation_after_last_witnessed_sth_not_detected(tmp_path):
    art = build(tmp_path, end_session=False)  # STHs at 5, 10, 15; one event in the tail
    full = run(art)
    assert full["overall"] == "PASS"
    assert full["unwitnessed_tail"]["events_in_tail"] == 1 and full["unwitnessed_tail"]["first_tail_seq"] == 15
    assert full["checks"]["session_end_counts"]["warnings"]  # session never closed: a warning only
    lines = read_lines(art.trace)[:-1]
    res = run(art, write_lines(tmp_path / "t.jsonl", lines))
    assert res["overall"] == "PASS"  # known limitation: silent truncation of the tail
    assert res["unwitnessed_tail"]["events_in_tail"] == 0


def test_withholding_last_witnessed_sth_only_widens_the_tail(tmp_path):
    art = build(tmp_path)
    sths = json.loads(art.witnessed_sths.read_text())
    (tmp_path / "s.json").write_text(json.dumps(sths[:-1]))
    res = run(art, sths=tmp_path / "s.json")
    assert res["overall"] == "PASS"
    assert res["unwitnessed_tail"]["events_in_tail"] == art.n_events - sths[-2]["tree_size"] > 0


def test_payloads_optional_redaction_is_not_tampering(tmp_path):
    art = build(tmp_path)
    lines = read_lines(art.trace)
    for l in lines:
        l.pop("payloads", None)
    res = run(art, write_lines(tmp_path / "t.jsonl", lines))
    assert res["overall"] == "PASS"
    pc = res["checks"]["payload_hashes"]
    assert pc["status"] == "PASS" and pc["redacted"] > 0 and pc["verified"] == 0 and "redacted" in pc["detail"]
    assert any(e["payload"]["input"] == "redacted" for e in res["events"])


def test_modified_payload_detected(tmp_path):
    art = build(tmp_path)
    lines = read_lines(art.trace)
    victim = next(i for i, l in enumerate(lines) if l.get("payloads"))
    h = next(iter(lines[victim]["payloads"]))
    lines[victim]["payloads"][h] = "I never sent that email"
    res = run(art, write_lines(tmp_path / "t.jsonl", lines))
    assert res["overall"] == "FAIL" and statuses(res)["payload_hashes"] == "FAIL"
    assert statuses(res)["event_signatures"] == "PASS" and statuses(res)["merkle_root_vs_witnessed_sths"] == "PASS"
    assert "MISMATCH" in json.dumps(res["events"][victim]["payload"])


def test_tampered_or_foreign_sth_entries_detected(tmp_path):
    art = build(tmp_path)
    sths = json.loads(art.witnessed_sths.read_text())
    forged = json.loads(json.dumps(sths))
    forged[1]["root_hash"] = "00" * 32
    (tmp_path / "f.json").write_text(json.dumps(forged))
    res = run(art, sths=tmp_path / "f.json")
    assert res["overall"] == "FAIL" and statuses(res)["sth_signatures"] == "FAIL"
    # a witness key the verifier was not given
    other = generate_private_key()
    save_public_key(other.public_key(), tmp_path / "other.pub")
    assert statuses(run(art, witness_pubs=[tmp_path / "other.pub"]))["sth_signatures"] == "FAIL"
    # no witnessed STH at all means the history is not anchored
    (tmp_path / "e.json").write_text("[]")
    res = run(art, sths=tmp_path / "e.json")
    assert res["overall"] == "FAIL" and statuses(res)["merkle_root_vs_witnessed_sths"] == "FAIL"


def test_witness_chain_consistency_checked_independently_of_trace(tmp_path):
    art = build(tmp_path)
    sths = json.loads(art.witnessed_sths.read_text())
    assert statuses(run(art))["witnessed_sth_consistency"] == "PASS"
    sths[2]["consistency_proof"][0] = "11" * 32  # proofs are unsigned; the verifier re-checks them
    (tmp_path / "s.json").write_text(json.dumps(sths))
    res = run(art, sths=tmp_path / "s.json")
    st = statuses(res)
    assert st["witnessed_sth_consistency"] == "FAIL" and st["merkle_root_vs_witnessed_sths"] == "PASS"
    del sths[2]  # an entry missing from the file: skipped step is a warning, not a failure
    (tmp_path / "g.json").write_text(json.dumps(sths))
    res = run(art, sths=tmp_path / "g.json")
    assert res["checks"]["witnessed_sth_consistency"]["warnings"]


# --- hand-built ledgers for cases the scripted pipeline cannot produce ------------------------


def mk_event(i, name=None, session="s", attrs=None):
    return {"trace_id": "a" * 32, "span_id": f"{i:016x}", "parent_span_id": None, "name": name or f"e{i}",
            "start_time_ns": 1000 + i, "end_time_ns": 2000 + i, "status": "OK", "attributes": attrs or {},
            "payload_hashes": {"input_sha256": None, "output_sha256": None}, "session_id": session}


def manual(tmp_path, committed):
    log, agent = generate_private_key(), generate_private_key()
    w = Witness(tmp_path / "w", log.public_key())
    led = Ledger(tmp_path / "l.db", log, agent, sth_interval=0)
    for i in range(4):
        led.append(mk_event(i))
    led.append(mk_event(4, SESSION_END_NAME, attrs={SESSION_COUNT_ATTR: committed}))
    w.submit(led.issue_sth().to_json_dict(), [])
    led.export_trace(tmp_path / "t.jsonl")
    w.export(tmp_path / "s.json")
    for name, k in (("log", log), ("agent", agent)):
        save_public_key(k.public_key(), tmp_path / f"{name}.pub")
    return V.verify_files(tmp_path / "t.jsonl", tmp_path / "log.pub", tmp_path / "agent.pub",
                          [tmp_path / "w" / "witness.pub"], tmp_path / "s.json")


def test_session_end_count_checked_against_actual_events(tmp_path):
    (tmp_path / "ok").mkdir()
    ok = manual(tmp_path / "ok", 4)
    assert ok["overall"] == "PASS" and statuses(ok)["session_end_counts"] == "PASS"
    (tmp_path / "bad").mkdir()
    bad = manual(tmp_path / "bad", 5)  # correctly signed, witnessed... but lies about the count
    assert bad["overall"] == "FAIL"
    assert statuses(bad)["session_end_counts"] == "FAIL"
    assert statuses(bad)["event_signatures"] == "PASS" and statuses(bad)["merkle_root_vs_witnessed_sths"] == "PASS"
    assert bad["checks"]["session_end_counts"]["failures"][0]["committed"] == 5


def test_same_size_different_roots_from_two_witnesses_flagged(tmp_path):
    log = generate_private_key()
    agent = generate_private_key()
    honest = Ledger(tmp_path / "h.db", log, agent, sth_interval=0)
    fork = Ledger(tmp_path / "f.db", log, generate_private_key(), sth_interval=0)
    for i in range(6):
        honest.append(mk_event(i))
        fork.append(mk_event(i, name=f"evil{i}"))
    wa, wb = Witness(tmp_path / "wa", log.public_key()), Witness(tmp_path / "wb", log.public_key())
    wa.submit(honest.issue_sth().to_json_dict(), [])
    wb.submit(fork.issue_sth().to_json_dict(), [])
    honest.export_trace(tmp_path / "t.jsonl")
    (tmp_path / "s.json").write_text(json.dumps(wa.sths() + wb.sths()))
    save_public_key(log.public_key(), tmp_path / "log.pub")
    save_public_key(agent.public_key(), tmp_path / "agent.pub")
    res = V.verify_files(tmp_path / "t.jsonl", tmp_path / "log.pub", tmp_path / "agent.pub",
                         [tmp_path / "wa" / "witness.pub", tmp_path / "wb" / "witness.pub"], tmp_path / "s.json")
    st = statuses(res)
    assert res["overall"] == "FAIL" and st["witnessed_sth_consistency"] == "FAIL"
    assert st["merkle_root_vs_witnessed_sths"] == "FAIL"  # the forked root cannot match this trace
