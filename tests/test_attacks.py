import hashlib
from pathlib import Path

from attacks.tamper import (
    DETECTED, NOT_DETECTED, SCENARIOS, format_table, run_all, run_scenario,
    scenario_1, scenario_2, scenario_3, scenario_4, scenario_5, scenario_6,
)
from demo.agent_scripted import produce_artifacts


def caught(row):
    return set(row.caught_by)


def setup(tmp_path):
    return produce_artifacts(tmp_path / "base")


def test_scenario_1_edit_without_signing_key_is_detected(tmp_path):
    row = run_scenario(scenario_1, tmp_path / "s", setup(tmp_path))
    assert (row.expected, row.actual) == (DETECTED, DETECTED)
    assert "event_signatures" in caught(row)  # a forged edit cannot carry a valid signature
    assert "merkle_root_vs_witnessed_sths" in caught(row)
    assert "seq_continuity" not in caught(row)
    lo, hi = row.result["first_broken_seq_range"]
    assert lo == hi  # exact: one event named


def test_scenario_2_mid_log_deletion_is_detected(tmp_path):
    row = run_scenario(scenario_2, tmp_path / "s", setup(tmp_path))
    assert (row.expected, row.actual) == (DETECTED, DETECTED)
    assert {"seq_continuity", "merkle_root_vs_witnessed_sths"} <= caught(row)
    assert "event_signatures" not in caught(row)  # survivors are individually authentic
    assert row.result["first_broken_seq_range"][0] == row.result["first_broken_seq_range"][1]


def test_scenario_3_truncation_before_last_witnessed_sth_is_detected(tmp_path):
    row = run_scenario(scenario_3, tmp_path / "s", setup(tmp_path))
    assert (row.expected, row.actual) == (DETECTED, DETECTED)
    assert caught(row) == {"merkle_root_vs_witnessed_sths"}  # nothing looks wrong inside what remains
    assert "truncated" in row.result["checks"]["merkle_root_vs_witnessed_sths"]["failures"][0]["problem"]


def test_scenario_4_truncation_after_last_witnessed_sth_is_NOT_detected(tmp_path):
    base = setup(tmp_path)
    t = scenario_4(tmp_path / "s", base)
    before = produce_and_verify_unmodified(t)
    row = run_scenario(scenario_4, tmp_path / "s2", base)
    assert (row.expected, row.actual) == (NOT_DETECTED, NOT_DETECTED)
    assert row.caught_by == [] and row.result["overall"] == "PASS"
    assert before["unwitnessed_tail"]["events_in_tail"] == 0  # the tail is gone, silently
    assert row.result["checks"]["session_end_counts"]["warnings"]  # only a warning: session never closed
    assert row.result["events_checked"] < t.base.n_events  # events really were removed


def produce_and_verify_unmodified(t):
    """Verify the ORIGINAL (untruncated) run for comparison: it passes and had a tail."""
    from tracelock.verify import verify_files
    res = verify_files(t.base.trace, t.base.log_pub, t.base.agent_pub, t.base.witness_pubs, t.base.witnessed_sths)
    assert res["overall"] == "PASS" and res["unwitnessed_tail"]["events_in_tail"] > 0
    return verify_files(t.trace, t.base.log_pub, t.base.agent_pub, t.base.witness_pubs, t.witnessed_sths)


def test_scenario_5_full_rewrite_detected_by_witnessed_state(tmp_path):
    base = setup(tmp_path)
    row = run_scenario(scenario_5, tmp_path / "s", base)
    assert (row.expected, row.actual) == (DETECTED, DETECTED)
    st = {k: c["status"] for k, c in row.result["checks"].items()}
    # Everything the attacker controls is internally perfect...
    for ok in ("event_signatures", "seq_continuity", "session_end_counts", "payload_hashes", "sth_signatures",
               "witnessed_sth_consistency"):
        assert st[ok] == "PASS", ok
    # ...and only the witnessed checkpoints expose it.
    assert caught(row) == {"merkle_root_vs_witnessed_sths"}
    text = " ".join(row.notes)
    assert "HTTP 409" in text and "different root_hash" in text and "consistency proof" in text
    assert "ACCEPTED" not in text


def test_scenario_6_unrecorded_action_is_NOT_detected(tmp_path):
    base = setup(tmp_path)
    t = scenario_6(tmp_path / "s", base)
    assert t.ground_truth["emails_actually_sent"] == t.ground_truth["emails_in_trace"] + 1
    row = run_scenario(scenario_6, tmp_path / "s2", base)
    assert (row.expected, row.actual) == (NOT_DETECTED, NOT_DETECTED)
    assert row.caught_by == [] and all(c["status"] == "PASS" for c in row.result["checks"].values())


def digest(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_runner_table_and_originals_untouched(tmp_path):
    base = produce_artifacts(tmp_path / "base")
    originals = {p: digest(p) for p in (base.trace, base.ledger_db, base.witnessed_sths)}
    originals.update({p: digest(p) for p in (base.out_dir / "witness_data").glob("*") if p.is_file()})
    rows = [run_scenario(fn, tmp_path / f"s{i}", base) for i, fn in enumerate(SCENARIOS, 1)]
    assert {p: digest(p) for p in originals} == originals  # attacks only ever touched copies
    assert [r.scenario for r in rows] == [1, 2, 3, 4, 5, 6] and all(r.matches for r in rows)
    table = format_table(rows)
    lines = [l for l in table.splitlines() if l.startswith("| ")]
    assert lines[0].split("|")[1:-1] == [" # ", " Scenario ", " Expected ", " Actual ", " Caught by "]
    assert len(lines) == 1 + 6
    assert table.count("NOT DETECTED | NOT DETECTED") == 2
    assert "known limitation" in table.lower() and "not bugs" in table
    assert "All outcomes match expectations: yes." in table


def test_run_all_end_to_end(tmp_path):
    rows = run_all(tmp_path)
    assert all(r.matches for r in rows)
    assert [r.actual for r in rows] == [DETECTED, DETECTED, DETECTED, NOT_DETECTED, DETECTED, NOT_DETECTED]
