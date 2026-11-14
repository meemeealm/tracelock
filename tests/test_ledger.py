import json
import sqlite3

import pytest

from tracelock.canonical import canonical_json, sha256_hex
from tracelock.ledger import (
    EVENT_FIELDS, SESSION_COUNT_ATTR, SESSION_END_NAME, Ledger, LedgerCorruptError,
)
from tracelock.merkle import MerkleTree, leaf_hash, verify_consistency, verify_inclusion
from tracelock.signing import generate_private_key, key_id, verify


def mk_event(i: int, session: str = "s1") -> dict:
    return {
        "trace_id": "a" * 32, "span_id": f"{i:016x}", "parent_span_id": None,
        "name": f"step-{i}", "start_time_ns": 1000 + i, "end_time_ns": 2000 + i,
        "status": "OK", "attributes": {"gen_ai.operation.name": "chat"},
        "payload_hashes": {"input_sha256": None, "output_sha256": None},
        "session_id": session,
    }


class Keys:
    def __init__(self):
        self.log, self.agent = generate_private_key(), generate_private_key()


def make_ledger(tmp_path, keys=None, interval=0):
    keys = keys or Keys()
    clock = iter(range(10_000, 10**9)).__next__
    return Ledger(tmp_path / "l.db", keys.log, keys.agent, sth_interval=interval, clock=clock), keys


def test_mk_event_has_exactly_the_required_fields():
    assert set(mk_event(0)) == EVENT_FIELDS


def test_append_assigns_seq_signs_and_persists(tmp_path):
    led, keys = make_ledger(tmp_path)
    for i in range(5):
        res = led.append(mk_event(i))
        assert res.seq == i
    for i in range(5):
        se = led.get_event(i)
        assert se.event["seq"] == i
        assert se.leaf_data == canonical_json(se.event)
        assert se.leaf_hash == leaf_hash(se.leaf_data)
        assert verify(keys.agent.public_key(), se.leaf_hash, se.signature)
        assert not verify(keys.log.public_key(), se.leaf_hash, se.signature)


def test_seq_cannot_be_supplied_by_caller(tmp_path):
    led, _ = make_ledger(tmp_path)
    with pytest.raises(ValueError):
        led.append({**mk_event(0), "seq": 99})
    with pytest.raises(ValueError):
        led.append({"name": "incomplete"})
    assert led.size == 0


def test_failed_append_leaves_no_gap(tmp_path):
    led, _ = make_ledger(tmp_path)
    led.append(mk_event(0))
    with pytest.raises(TypeError):
        led.append({**mk_event(1), "start_time_ns": 1.5})  # float rejected
    with pytest.raises(TypeError):
        led.append(mk_event(1), payloads=["not bytes"])
    assert led.size == 1
    assert led.append(mk_event(1)).seq == 1


def test_inclusion_proofs_verify_against_root(tmp_path):
    led, _ = make_ledger(tmp_path)
    for i in range(11):
        led.append(mk_event(i))
    root = led.root
    for i in range(11):
        se = led.get_event(i)
        assert verify_inclusion(se.leaf_hash, i, 11, led.inclusion_proof(i), root)


def test_matches_independent_merkle_tree(tmp_path):
    led, _ = make_ledger(tmp_path)
    ref = MerkleTree()
    for i in range(9):
        led.append(mk_event(i))
        ref.append(led.get_event(i).leaf_data)
    assert led.root == ref.root()


def test_auto_sth_every_n_events(tmp_path):
    led, keys = make_ledger(tmp_path, interval=3)
    for i in range(7):
        led.append(mk_event(i))
    sths = led.sths()
    assert [s.tree_size for s in sths] == [3, 6]
    for s in sths:
        assert s.log_id == key_id(keys.log.public_key())
        assert verify(keys.log.public_key(), s.signed_bytes(), s.signature)
        assert s.root_hash == led.root_at(s.tree_size).hex()
    # consecutive STHs are consistent
    a, b = sths
    assert verify_consistency(
        a.tree_size, b.tree_size, bytes.fromhex(a.root_hash), bytes.fromhex(b.root_hash),
        led.consistency_proof(a.tree_size, b.tree_size),
    )


def test_manual_sth_and_signature_binds_fields(tmp_path):
    led, keys = make_ledger(tmp_path)
    led.append(mk_event(0))
    s = led.issue_sth()
    assert led.latest_sth() == s and s.tree_size == 1
    forged = {**s.sth_dict(), "tree_size": 2}
    assert not verify(keys.log.public_key(), canonical_json(forged), s.signature)
    assert set(s.to_json_dict()) == {"tree_size", "root_hash", "timestamp_ns", "log_id", "signature"}


def test_session_end_commits_count_and_issues_sth(tmp_path):
    led, _ = make_ledger(tmp_path, interval=0)
    for i in range(4):
        led.append(mk_event(i, "A"))
    led.append(mk_event(4, "B"))
    res = led.end_session("A")
    ev = led.get_event(res.seq).event
    assert ev["name"] == SESSION_END_NAME
    assert ev["attributes"][SESSION_COUNT_ATTR] == 4  # B's event and itself excluded
    assert res.sth is not None and res.sth.tree_size == led.size
    with pytest.raises(ValueError):
        led.end_session("A")
    assert led.get_event(led.end_session("B").seq).event["attributes"][SESSION_COUNT_ATTR] == 1


def test_rebuild_from_stored_leaves(tmp_path):
    led, keys = make_ledger(tmp_path, interval=4)
    for i in range(10):
        led.append(mk_event(i))
    led.end_session("s1")
    root, size, n_sths = led.root, led.size, len(led.sths())
    led.close()

    led2, _ = make_ledger(tmp_path, keys, interval=4)
    assert (led2.root, led2.size, len(led2.sths())) == (root, size, n_sths)
    assert led2.append(mk_event(11)).seq == size  # continues cleanly
    with pytest.raises(ValueError):
        led2.end_session("s1")  # "already ended" survives restart


def test_rebuild_restores_session_counts(tmp_path):
    led, keys = make_ledger(tmp_path)
    for i in range(3):
        led.append(mk_event(i, "S"))
    led.close()
    led2, _ = make_ledger(tmp_path, keys)
    led2.append(mk_event(3, "S"))
    seq = led2.end_session("S").seq
    assert led2.get_event(seq).event["attributes"][SESSION_COUNT_ATTR] == 4


def test_rebuild_detects_local_corruption(tmp_path):
    led, keys = make_ledger(tmp_path)
    for i in range(3):
        led.append(mk_event(i))
    led.close()
    db = sqlite3.connect(tmp_path / "l.db")
    row = db.execute("SELECT leaf_data FROM events WHERE seq=1").fetchone()[0]
    db.execute("UPDATE events SET leaf_data=? WHERE seq=1", (row.replace(b"step-1", b"step-X"),))
    db.commit(); db.close()
    with pytest.raises(LedgerCorruptError):
        make_ledger(tmp_path, keys)


def test_rebuild_detects_deleted_event(tmp_path):
    led, keys = make_ledger(tmp_path)
    for i in range(4):
        led.append(mk_event(i))
    led.close()
    db = sqlite3.connect(tmp_path / "l.db")
    db.execute("DELETE FROM events WHERE seq=2"); db.commit(); db.close()
    with pytest.raises(LedgerCorruptError):
        make_ledger(tmp_path, keys)


def test_payloads_separate_and_redactable(tmp_path):
    led, keys = make_ledger(tmp_path)
    blob = b"secret prompt text"
    led.append(mk_event(0), payloads=[blob, blob])  # duplicate blob is fine
    h = sha256_hex(blob)
    assert led.get_payload(h) == blob
    root = led.root
    led.close()
    db = sqlite3.connect(tmp_path / "l.db")
    db.execute("DELETE FROM payloads"); db.commit(); db.close()
    led2, _ = make_ledger(tmp_path, keys)
    assert led2.get_payload(h) is None
    assert led2.root == root  # redaction does not touch the tree


def test_iter_events_in_seq_order(tmp_path):
    led, _ = make_ledger(tmp_path)
    for i in range(6):
        led.append(mk_event(i))
    assert [e.seq for e in led.iter_events()] == list(range(6))
    assert json.loads(next(led.iter_events()).leaf_data)["name"] == "step-0"
