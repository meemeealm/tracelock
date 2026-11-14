import json

import pytest

from tracelock.canonical import canonical_json
from tracelock.ledger import Ledger
from tracelock.merkle import EMPTY_ROOT
from tracelock.signing import generate_private_key, key_id, save_public_key, verify
from tracelock.witness import (
    Witness, WitnessClient, WitnessError, cosign_file, main as witness_main,
    make_server, serve_in_thread, server_url,
)
from tracelock.signing import load_public_key


def mk_event(i, tag="a"):
    return {
        "trace_id": "a" * 32, "span_id": f"{i:016x}", "parent_span_id": None,
        "name": f"{tag}-{i}", "start_time_ns": 1000 + i, "end_time_ns": 2000 + i,
        "status": "OK", "attributes": {}, "payload_hashes": {"input_sha256": None, "output_sha256": None},
        "session_id": "s",
    }


def mk_ledger(tmp_path, name, log_key, n=0, tag="a", **kw):
    led = Ledger(tmp_path / f"{name}.db", log_key, generate_private_key(), sth_interval=0, **kw)
    for i in range(n):
        led.append(mk_event(i, tag))
    return led


def submit(w, led, old_size=None):
    sth = led.issue_sth()
    last = old_size if old_size is not None else (w.sths()[-1]["tree_size"] if w.sths() else 0)
    proof = [p.hex() for p in led.consistency_proof(last, sth.tree_size)] if sth.tree_size >= last else []
    return w.submit(sth.to_json_dict(), proof)


def status_of(fn):
    try:
        fn()
    except WitnessError as e:
        return e.status
    return None


def test_first_sth_is_cosigned_and_stored(tmp_path):
    log = generate_private_key()
    led = mk_ledger(tmp_path, "l", log, 3)
    w = Witness(tmp_path / "w", log.public_key())
    e = submit(w, led)
    fields = {k: e[k] for k in ("tree_size", "root_hash", "timestamp_ns", "log_id")}
    wpub = w._key.public_key()
    assert e["witness_id"] == key_id(wpub)
    assert verify(wpub, canonical_json(fields), bytes.fromhex(e["witness_signature"]))
    assert not verify(log.public_key(), canonical_json(fields), bytes.fromhex(e["witness_signature"]))
    assert len(list((tmp_path / "w").glob("sth-*.json"))) == 1


def test_consistent_chain_accepted_and_proofs_stored(tmp_path):
    log = generate_private_key()
    led = mk_ledger(tmp_path, "l", log, 3)
    w = Witness(tmp_path / "w", log.public_key())
    submit(w, led)
    for i in range(3, 8):
        led.append(mk_event(i))
    e2 = submit(w, led)
    for i in range(8, 15):
        led.append(mk_event(i))
    e3 = submit(w, led)
    assert (e2["previous_tree_size"], e3["previous_tree_size"]) == (3, 8)
    assert len(e3["consistency_proof"]) > 0
    assert [e["tree_size"] for e in w.sths()] == [3, 8, 15]


def test_fork_is_rejected_with_409_and_logged(tmp_path):
    log = generate_private_key()
    honest = mk_ledger(tmp_path, "h", log, 3)
    w = Witness(tmp_path / "w", log.public_key())
    submit(w, honest)
    fork = mk_ledger(tmp_path, "f", log, 8, tag="evil")  # same log key, rewritten history
    sth = fork.issue_sth()
    proof = [p.hex() for p in fork.consistency_proof(3, 8)]
    assert status_of(lambda: w.submit(sth.to_json_dict(), proof)) == 409
    lines = (tmp_path / "w" / "equivocation.log").read_text().splitlines()
    assert len(lines) == 1
    ev = json.loads(lines[0])
    assert "inconsistent" in ev["reason"] and ev["submitted"]["tree_size"] == 8
    assert ev["last_witnessed"]["tree_size"] == 3
    assert len(w.sths()) == 1  # nothing was cosigned


def test_rollback_and_same_size_cases(tmp_path):
    log = generate_private_key()
    led = mk_ledger(tmp_path, "l", log, 6)
    w = Witness(tmp_path / "w", log.public_key())
    first = submit(w, led)
    again = w.submit({k: first[k] for k in ("tree_size", "root_hash", "timestamp_ns", "log_id", "signature")}, [])
    assert again == first and len(w.sths()) == 1  # idempotent
    small = mk_ledger(tmp_path, "s", log, 4, tag="a")
    assert status_of(lambda: w.submit(small.issue_sth().to_json_dict(), [])) == 409  # rollback
    other = mk_ledger(tmp_path, "o", log, 6, tag="evil")
    assert status_of(lambda: w.submit(other.issue_sth().to_json_dict(), [])) == 409  # same size, other root
    assert len((tmp_path / "w" / "equivocation.log").read_text().splitlines()) == 2


def test_bad_log_signature_and_malformed_rejected(tmp_path):
    log = generate_private_key()
    led = mk_ledger(tmp_path, "l", log, 3)
    w = Witness(tmp_path / "w", log.public_key())
    sth = led.issue_sth().to_json_dict()
    assert status_of(lambda: w.submit({**sth, "tree_size": 4}, [])) == 403  # fields changed after signing
    impostor = mk_ledger(tmp_path, "i", generate_private_key(), 3)
    assert status_of(lambda: w.submit(impostor.issue_sth().to_json_dict(), [])) == 403
    assert status_of(lambda: w.submit({"tree_size": 3}, [])) == 400
    assert status_of(lambda: w.submit({**sth, "root_hash": "zz"}, [])) == 400
    assert status_of(lambda: w.submit(sth, ["nothex"])) == 400
    assert status_of(lambda: w.submit(sth, ["00" * 32])) == 400  # first STH must have empty proof
    assert w.sths() == []


def test_own_key_own_dir_and_persistence(tmp_path):
    log = generate_private_key()
    led = mk_ledger(tmp_path, "l", log, 3)
    w1 = Witness(tmp_path / "w1", log.public_key())
    w2 = Witness(tmp_path / "w2", log.public_key())
    assert w1.witness_id != w2.witness_id
    assert (tmp_path / "w1" / "witness.key").exists() and (tmp_path / "w1" / "witness.pub").exists()
    submit(w1, led)
    again = Witness(tmp_path / "w1", log.public_key())  # restart
    assert again.witness_id == w1.witness_id and again.sths() == w1.sths()
    assert w2.sths() == []


def test_http_service_and_ledger_hook(tmp_path):
    log = generate_private_key()
    w = Witness(tmp_path / "w", log.public_key())
    server = make_server(w)
    serve_in_thread(server)
    try:
        led = Ledger(tmp_path / "l.db", log, generate_private_key(), sth_interval=2)
        led.sth_hook = WitnessClient(server_url(server), led.consistency_proof).submit
        for i in range(5):
            led.append(mk_event(i))
        led.end_session("s")
        assert led.hook_errors == []
        assert [e["tree_size"] for e in w.sths()] == [2, 4, 6]
        # a forked log is refused over HTTP, and the ledger records that without crashing
        fork = Ledger(tmp_path / "f.db", log, generate_private_key(), sth_interval=2)
        fork.sth_hook = WitnessClient(server_url(server), fork.consistency_proof).submit
        for i in range(8):
            fork.append(mk_event(i, "evil"))
        # sizes 2,4 are rollbacks, 6 is a different root at a witnessed size, 8 fails consistency
        assert fork.size == 8 and len(fork.hook_errors) == 4
        assert all("WitnessError" in e for e in fork.hook_errors)
        assert "consistency proof" in fork.hook_errors[-1]
        assert len(w.sths()) == 3
        assert (tmp_path / "w" / "equivocation.log").exists()
    finally:
        server.shutdown(); server.server_close()


def test_http_error_statuses(tmp_path):
    import urllib.error, urllib.request
    log = generate_private_key()
    w = Witness(tmp_path / "w", log.public_key())
    server = make_server(w)
    serve_in_thread(server)
    try:
        base = server_url(server)
        def post(path, body):
            req = urllib.request.Request(base + path, data=body, headers={"Content-Type": "application/json"})
            try:
                return urllib.request.urlopen(req).status
            except urllib.error.HTTPError as e:
                return e.code
        assert post("/sth", b"not json") == 400
        assert post("/sth", b'{"nope": 1}') == 400
        assert post("/other", b"{}") == 404
        assert json.loads(urllib.request.urlopen(base + "/sths").read()) == []
    finally:
        server.shutdown(); server.server_close()


def test_hook_failure_never_breaks_append(tmp_path):
    log = generate_private_key()
    led = Ledger(tmp_path / "l.db", log, generate_private_key(), sth_interval=1)
    led.sth_hook = WitnessClient("http://127.0.0.1:9", led.consistency_proof, timeout=0.5).submit  # nothing listens
    for i in range(3):
        led.append(mk_event(i))
    assert led.size == 3 and len(led.hook_errors) == 3
    assert len(led.sths()) == 3


def test_file_witness_cosign_and_cli(tmp_path):
    log = generate_private_key()
    save_public_key(log.public_key(), tmp_path / "log.pub")
    led = mk_ledger(tmp_path, "l", log, 3)
    sth1 = led.issue_sth()
    (tmp_path / "sth1.json").write_text(json.dumps(sth1.to_json_dict()))
    e1 = cosign_file(tmp_path / "gitrepo", tmp_path / "log.pub", tmp_path / "sth1.json")
    for i in range(3, 7):
        led.append(mk_event(i))
    sth2 = led.issue_sth()
    (tmp_path / "sth2.json").write_text(json.dumps(sth2.to_json_dict()))
    (tmp_path / "proof.json").write_text(json.dumps([p.hex() for p in led.consistency_proof(3, 7)]))
    assert witness_main(["cosign", "--data-dir", str(tmp_path / "gitrepo"), "--log-pubkey",
                         str(tmp_path / "log.pub"), "--sth", str(tmp_path / "sth2.json"),
                         "--proof", str(tmp_path / "proof.json")]) == 0
    files = sorted(p.name for p in (tmp_path / "gitrepo").glob("sth-*.json"))
    assert len(files) == 2 and files[0].startswith("sth-000000000003")
    # a bad proof is rejected with exit code 1
    (tmp_path / "bad.json").write_text("[]")
    led.append(mk_event(7))
    (tmp_path / "sth3.json").write_text(json.dumps(led.issue_sth().to_json_dict()))
    assert witness_main(["cosign", "--data-dir", str(tmp_path / "gitrepo"), "--log-pubkey",
                         str(tmp_path / "log.pub"), "--sth", str(tmp_path / "sth3.json"),
                         "--proof", str(tmp_path / "bad.json")]) == 1
    assert witness_main(["export", "--data-dir", str(tmp_path / "gitrepo"), "--out", str(tmp_path / "x.json")]) == 0
    assert [e["tree_size"] for e in json.loads((tmp_path / "x.json").read_text())] == [3, 7]
