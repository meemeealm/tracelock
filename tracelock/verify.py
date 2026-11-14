#!/usr/bin/env python3
"""TraceLock STANDALONE verifier.

Deliberately imports NOTHING from the tracelock package (no ledger, processor,
witness, merkle, canonical or signing): only the stdlib and `cryptography`. It
carries its own small copy of canonical JSON and the RFC 6962 verification
functions (tests cross-check these against tracelock.merkle).

Inputs
  --trace             JSONL: {"event": {...}, "signature": hex[, "payloads": {sha256: text}]}
  --log-pubkey        log's Ed25519 public key (hex or PEM)
  --agent-pubkey      agent/operator Ed25519 public key (signs each event)
  --witness-pubkey    witness public key(s); repeatable
  --witnessed-sths    JSON array of witnessed STHs (as served by the witness)
Output: JSON result on stdout (and --out). Exit code 0 = PASS, 1 = FAIL, 2 = bad input.

What a PASS means is limited: see "unwitnessed_tail" and the README limitations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VERIFIER_VERSION = "1"
SESSION_END_NAME = "session_end"
SESSION_COUNT_ATTR = "tracelock.session.event_count"
EMPTY_ROOT = hashlib.sha256(b"").digest()
MAX_LISTED = 20  # cap on failure details per check

# ---------------------------------------------------------------------------
# Canonical JSON (own copy; must match tracelock.canonical byte for byte)
# ---------------------------------------------------------------------------


def _has_float(o: Any) -> bool:
    if isinstance(o, float):
        return True
    if isinstance(o, dict):
        return any(_has_float(v) for v in o.values())
    if isinstance(o, list):
        return any(_has_float(v) for v in o)
    return False


def canonical_json(o: Any) -> bytes:
    if _has_float(o):
        raise ValueError("float in canonical JSON")
    return json.dumps(
        o, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# RFC 6962 (own copy): hashing, root accumulation, proof verification
# ---------------------------------------------------------------------------


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _is_pow2(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


class RootAccumulator:
    """Incrementally computes the RFC 6962 root as leaf hashes are appended."""

    def __init__(self) -> None:
        self._frontier: list[tuple[int, bytes]] = []

    def append(self, h: bytes) -> None:
        size, node = 1, h
        while self._frontier and self._frontier[-1][0] == size:
            _, left = self._frontier.pop()
            node = node_hash(left, node)
            size *= 2
        self._frontier.append((size, node))

    def root(self) -> bytes:
        if not self._frontier:
            return EMPTY_ROOT
        r = self._frontier[-1][1]
        for _, h in reversed(self._frontier[:-1]):
            r = node_hash(h, r)
        return r


def verify_inclusion(lh: bytes, index: int, size: int, proof: list[bytes], root: bytes) -> bool:
    """RFC 9162 2.1.3.2 (accepts RFC 6962 audit paths)."""
    if size <= 0 or not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, lh
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(
    old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]
) -> bool:
    """RFC 9162 2.1.4.2 (accepts RFC 6962 consistency proofs)."""
    if old_size < 0 or new_size < old_size:
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size == 0:
        return not proof and old_root == EMPTY_ROOT
    if not proof:
        return False
    path = list(proof)
    if _is_pow2(old_size):
        path.insert(0, old_root)
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0


# ---------------------------------------------------------------------------
# Keys and signatures
# ---------------------------------------------------------------------------


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    raw = Path(path).read_bytes()
    if raw.lstrip().startswith(b"-----BEGIN"):
        key = serialization.load_pem_public_key(raw)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError(f"{path}: not an Ed25519 public key")
        return key
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(raw.decode().strip()))


def key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def sig_ok(pub: Ed25519PublicKey, msg: bytes, sig_hex: Any) -> bool:
    try:
        pub.verify(bytes.fromhex(sig_hex), msg)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _runs(nums: list[int]) -> list[list[int]]:
    """Collapse integers into inclusive [first, last] runs of consecutive values."""
    out: list[list[int]] = []
    for n in sorted(set(nums)):
        if out and n == out[-1][1] + 1:
            out[-1][1] = n
        else:
            out.append([n, n])
    return out


def _check(status: str, detail: str, ranges: list[list[int]] | None = None,
           failures: list[Any] | None = None, **extra: Any) -> dict[str, Any]:
    r: dict[str, Any] = {"status": status, "detail": detail, "ranges": ranges or []}
    if failures:
        r["failures"] = failures[:MAX_LISTED]
        if len(failures) > MAX_LISTED:
            r["failures_truncated"] = len(failures) - MAX_LISTED
    r.update(extra)
    return r


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------


def run_checks(
    records: list[Any],
    format_errors: list[str],
    log_pub: Ed25519PublicKey,
    agent_pub: Ed25519PublicKey,
    witness_pubs: list[Ed25519PublicKey],
    sth_entries: list[Any],
) -> dict[str, Any]:
    n = len(records)
    log_id = key_id(log_pub)
    witness_keys = {key_id(w): w for w in witness_pubs}

    # Per-event working data. `events[i]` is the event dict (or {} if malformed).
    events: list[dict[str, Any]] = []
    leaf_hashes: list[bytes] = []
    info: list[dict[str, Any]] = []
    for i, rec in enumerate(records):
        ev = rec.get("event") if isinstance(rec, dict) else None
        issues: list[str] = []
        lh = leaf_hash(b"<malformed event>")
        if not isinstance(ev, dict):
            issues.append("malformed record")
            ev = {}
        else:
            try:
                lh = leaf_hash(canonical_json(ev))
            except ValueError as exc:
                issues.append(f"not canonicalisable: {exc}")
        events.append(ev)
        leaf_hashes.append(lh)
        info.append({
            "index": i, "seq": ev.get("seq"), "name": ev.get("name"),
            "session_id": ev.get("session_id"), "ok": True, "issues": issues,
            "payload": {"input": "absent", "output": "absent"},
        })

    def flag(i: int, msg: str) -> None:
        info[i]["ok"] = False
        info[i]["issues"].append(msg)

    for i in range(n):
        if info[i]["issues"]:
            info[i]["ok"] = False

    def seq_of(i: int) -> int:
        s = events[i].get("seq")
        return s if _is_int(s) else i

    checks: dict[str, dict[str, Any]] = {}

    # trace_format -----------------------------------------------------------
    bad_fmt = list(format_errors) + [f"record {i}: {x}" for i in range(n) for x in info[i]["issues"]]
    checks["trace_format"] = (
        _check("FAIL", f"{len(bad_fmt)} malformed record(s)", failures=bad_fmt)
        if bad_fmt else _check("PASS", f"{n} records parsed")
    )

    # witnessed STH signatures ---------------------------------------------------
    valid: list[dict[str, Any]] = []
    sth_report: list[dict[str, Any]] = []
    sth_fail: list[str] = []
    for k, e in enumerate(sth_entries):
        problems: list[str] = []
        try:
            fields = {f: e[f] for f in ("tree_size", "root_hash", "timestamp_ns", "log_id")}
            if not (_is_int(fields["tree_size"]) and fields["tree_size"] >= 0):
                problems.append("bad tree_size")
            rh = fields["root_hash"]
            if not (isinstance(rh, str) and len(rh) == 64 and bytes.fromhex(rh) is not None):
                problems.append("bad root_hash")
            if not _is_int(fields["timestamp_ns"]):
                problems.append("bad timestamp_ns")
            msg = canonical_json(fields)
            if fields["log_id"] != log_id:
                problems.append("log_id does not match the supplied log public key")
            if not sig_ok(log_pub, msg, e.get("signature")):
                problems.append("invalid log signature")
            wpub = witness_keys.get(e.get("witness_id"))
            if wpub is None:
                problems.append("witness_id is not one of the supplied witness keys")
            elif not sig_ok(wpub, msg, e.get("witness_signature")):
                problems.append("invalid witness signature")
        except (KeyError, TypeError, ValueError) as exc:
            problems.append(f"malformed STH entry: {exc!r}")
        rep = {"entry": k, "tree_size": e.get("tree_size") if isinstance(e, dict) else None,
               "witness_id": e.get("witness_id") if isinstance(e, dict) else None,
               "valid": not problems, "problems": problems, "root_matches_trace": None}
        sth_report.append(rep)
        if problems:
            sth_fail.append(f"STH entry {k} (size {rep['tree_size']}): " + "; ".join(problems))
        else:
            valid.append(e)
    checks["sth_signatures"] = (
        _check("FAIL", f"{len(sth_fail)} of {len(sth_entries)} witnessed STH(s) invalid; "
               "invalid entries are ignored by later checks", failures=sth_fail)
        if sth_fail else _check("PASS", f"{len(valid)} witnessed STH(s) carry valid log and witness signatures")
    )

    # (a) per-event signatures -------------------------------------------------
    bad_sig: list[int] = []
    for i, rec in enumerate(records):
        sig = rec.get("signature") if isinstance(rec, dict) else None
        if not sig_ok(agent_pub, leaf_hashes[i], sig):
            flag(i, "invalid agent signature")
            bad_sig.append(seq_of(i))
    checks["event_signatures"] = (
        _check("FAIL", f"{len(bad_sig)} event(s) with an invalid signature", _runs(bad_sig),
               [f"seq {s}" for s in bad_sig])
        if bad_sig else _check("PASS", f"all {n} event signatures valid")
    )

    # (b) seq continuity ---------------------------------------------------------
    anomalies: list[dict[str, Any]] = []
    cont_ranges: list[list[int]] = []
    expected, seen = 0, set()
    for i, ev in enumerate(events):
        s = ev.get("seq")
        if not _is_int(s):
            anomalies.append({"index": i, "problem": "missing or non-integer seq"})
            flag(i, "missing or non-integer seq")
            continue
        if s == expected:
            expected += 1
        elif s > expected:
            anomalies.append({"index": i, "problem": "gap", "missing": [expected, s - 1]})
            cont_ranges.append([expected, s - 1])
            flag(i, f"gap: seq {expected}..{s - 1} missing before this event")
            expected = s + 1
        else:
            kind = "duplicate" if s in seen else "reordered"
            anomalies.append({"index": i, "problem": kind, "seq": s, "expected": expected})
            cont_ranges.append([s, s])
            flag(i, f"{kind} seq {s} (expected {expected})")
        seen.add(s)
    checks["seq_continuity"] = (
        _check("FAIL", f"{len(anomalies)} continuity anomaly(ies)", _runs([x for r in cont_ranges for x in range(r[0], r[1] + 1)]) if cont_ranges else [], anomalies)
        if anomalies else _check("PASS", f"seq 0..{n - 1} contiguous, no duplicates or reordering" if n else "empty trace")
    )

    # (c) recomputed root vs every witnessed STH -------------------------------------
    unique = sorted({(e["tree_size"], e["root_hash"]) for e in valid})
    if not unique:
        checks["merkle_root_vs_witnessed_sths"] = _check(
            "FAIL", "no valid witnessed STH: the history is not anchored to any witness")
    else:
        wanted = {s for s, _ in unique if s <= n}
        roots: dict[int, bytes] = {0: EMPTY_ROOT} if 0 in wanted else {}
        acc = RootAccumulator()
        for i, lh in enumerate(leaf_hashes, 1):
            acc.append(lh)
            if i in wanted:
                roots[i] = acc.root()
        prev_ok, fails, ranges, passed = 0, [], [], 0
        for size, root_hex in unique:
            ok = size <= n and roots[size].hex() == root_hex
            for rep in sth_report:
                if rep["valid"] and rep["tree_size"] == size and sth_entries[rep["entry"]]["root_hash"] == root_hex:
                    rep["root_matches_trace"] = ok
            if ok:
                passed += 1
                prev_ok = max(prev_ok, size)
            elif size > n:
                fails.append({"tree_size": size, "problem": f"trace has only {n} events (truncated or events deleted)"})
                ranges.append([n, size - 1])
            else:
                fails.append({"tree_size": size, "problem": "recomputed root differs from witnessed root"})
                ranges.append([prev_ok, size - 1])  # last good prefix .. this checkpoint
        checks["merkle_root_vs_witnessed_sths"] = (
            _check("FAIL", f"{len(fails)} of {len(unique)} witnessed root(s) do not match the trace", ranges, fails)
            if fails else _check("PASS", f"recomputed root matches all {len(unique)} witnessed STH(s)")
        )

    # (d) consistency between successive witnessed STHs --------------------------------
    d_fail: list[Any] = []
    d_ranges: list[list[int]] = []
    d_warn: list[str] = []
    by_size: dict[int, set[str]] = {}
    by_witness: dict[str, list[dict[str, Any]]] = {}
    for e in valid:
        by_size.setdefault(e["tree_size"], set()).add(e["root_hash"])
        by_witness.setdefault(e["witness_id"], []).append(e)
    for size, rs in sorted(by_size.items()):
        if len(rs) > 1:
            d_fail.append({"tree_size": size, "problem": "different roots witnessed at the same tree_size (equivocation)"})
            d_ranges.append([0, max(size - 1, 0)])
    pairs = 0
    for wid, chain in by_witness.items():
        chain.sort(key=lambda e: e["tree_size"])
        for a, b in zip(chain, chain[1:]):
            if b["tree_size"] == a["tree_size"]:
                continue
            if b.get("previous_tree_size") != a["tree_size"]:
                d_warn.append(f"witness {wid[:12]}: STH(s) between size {a['tree_size']} and {b['tree_size']} "
                              "are absent from the file; that step is not independently checked")
                continue
            try:
                proof = [bytes.fromhex(x) for x in b["consistency_proof"]]
                ok = verify_consistency(a["tree_size"], b["tree_size"], bytes.fromhex(a["root_hash"]),
                                        bytes.fromhex(b["root_hash"]), proof)
            except (KeyError, TypeError, ValueError):
                ok = False
            pairs += 1
            if not ok:
                d_fail.append({"witness": wid[:12], "from": a["tree_size"], "to": b["tree_size"],
                               "problem": "consistency proof does not verify"})
                d_ranges.append([a["tree_size"], b["tree_size"] - 1])
    if not valid:
        checks["witnessed_sth_consistency"] = _check("FAIL", "no valid witnessed STH to compare")
    elif d_fail:
        checks["witnessed_sth_consistency"] = _check("FAIL", f"{len(d_fail)} inconsistency(ies) among witnessed STHs", d_ranges, d_fail, warnings=d_warn)
    else:
        checks["witnessed_sth_consistency"] = _check(
            "PASS", f"{pairs} successive witnessed STH pair(s) verified" if pairs else "fewer than two comparable witnessed STHs",
            warnings=d_warn)

    # (e) session_end count vs actual events ---------------------------------------------
    sessions: dict[str, list[int]] = {}
    for i, ev in enumerate(events):
        sessions.setdefault(str(ev.get("session_id")), []).append(i)
    e_fail: list[Any] = []
    e_ranges: list[list[int]] = []
    e_warn: list[str] = []
    ends_checked = 0
    for sid, idxs in sessions.items():
        ends = [i for i in idxs if events[i].get("name") == SESSION_END_NAME]
        actual = len(idxs) - len(ends)
        if not ends:
            e_warn.append(f"session {sid!r} has no session_end event (not closed, or its tail was cut)")
            continue
        if len(ends) > 1:
            e_fail.append({"session": sid, "problem": f"{len(ends)} session_end events"})
        end = ends[-1]
        committed = (events[end].get("attributes") or {}).get(SESSION_COUNT_ATTR)
        ends_checked += 1
        if committed != actual:
            e_fail.append({"session": sid, "problem": "session_end count differs from events found",
                           "committed": committed, "found": actual})
            e_ranges.append([seq_of(end), seq_of(end)])  # where the false commitment sits
            flag(end, f"session_end commits {committed} events but {actual} found")
    checks["session_end_counts"] = (
        _check("FAIL", f"{len(e_fail)} session count mismatch(es)", e_ranges, e_fail, warnings=e_warn)
        if e_fail else _check("PASS", f"{ends_checked} session_end count(s) match", warnings=e_warn)
    )

    # (f) payload hashes -------------------------------------------------------------------
    verified = redacted = mismatched = 0
    f_fail: list[Any] = []
    f_seqs: list[int] = []
    for i, (rec, ev) in enumerate(zip(records, events)):
        payloads = rec.get("payloads") if isinstance(rec, dict) else None
        payloads = payloads if isinstance(payloads, dict) else {}
        hashes = ev.get("payload_hashes")
        hashes = hashes if isinstance(hashes, dict) else {}
        for field, label in (("input_sha256", "input"), ("output_sha256", "output")):
            h = hashes.get(field)
            if h is None:
                continue
            text = payloads.get(h)
            if not isinstance(text, str):
                info[i]["payload"][label] = "redacted"
                redacted += 1
            elif hashlib.sha256(text.encode("utf-8")).hexdigest() == h:
                info[i]["payload"][label] = "verified"
                verified += 1
            else:
                info[i]["payload"][label] = "MISMATCH"
                mismatched += 1
                flag(i, f"{label} payload does not match its hash")
                f_fail.append({"seq": seq_of(i), "field": label})
                f_seqs.append(seq_of(i))
    checks["payload_hashes"] = (
        _check("FAIL", f"{mismatched} payload(s) do not match their hash (tampered)", _runs(f_seqs), f_fail,
               verified=verified, redacted=redacted)
        if mismatched else _check("PASS", f"{verified} payload(s) verified; {redacted} payload redacted (not a tamper signal)",
                                  verified=verified, redacted=redacted)
    )

    # Result assembly ---------------------------------------------------------------------
    # Exact checks name the broken events; coarse checks only bound where a break lies
    # (e.g. "somewhere after the last good checkpoint"). Report the earliest broken range;
    # if that is only a bound, narrow it to the earliest exact finding inside it.
    exact_names = {"event_signatures", "seq_continuity", "payload_hashes"}
    failing = [(r, name in exact_names) for name, c in checks.items() if c["status"] == "FAIL" for r in c["ranges"]]
    first_range = None
    if failing:
        first, is_exact = min(failing, key=lambda x: (x[0][0], x[0][1] - x[0][0]))
        if not is_exact:
            inside = [r for r, ex in failing if ex and r[0] >= first[0] and r[1] <= first[1]]
            if inside:
                first = min(inside)
        first_range = first
    overall = "FAIL" if any(c["status"] == "FAIL" for c in checks.values()) else "PASS"

    last_size = max((e["tree_size"] for e in valid), default=0)
    last_ts = max((e["timestamp_ns"] for e in valid if e["tree_size"] == last_size), default=None)
    tail_count = max(0, n - last_size)
    tail = {
        "last_witnessed_tree_size": last_size,
        "last_witnessed_timestamp_ns": last_ts,
        "events_in_tail": tail_count,
        "first_tail_seq": seq_of(last_size) if tail_count else None,
        "last_tail_seq": seq_of(n - 1) if tail_count else None,
        "note": ("Events after the last witnessed STH are protected only by their own signatures; "
                 "a silent truncation of this tail cannot be detected."),
    }
    return {
        "verifier_version": VERIFIER_VERSION,
        "overall": overall,
        "first_broken_seq_range": first_range,
        "events_checked": n,
        "checks": checks,
        "unwitnessed_tail": tail,
        "witnessed_sths": sth_report,
        "events": info,
    }


# ---------------------------------------------------------------------------
# File front-end
# ---------------------------------------------------------------------------


def load_trace(path: str | Path) -> tuple[list[Any], list[str]]:
    records: list[Any] = []
    errors: list[str] = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except ValueError as exc:
                errors.append(f"line {lineno}: invalid JSON ({exc})")
                records.append(None)  # keep position so seq/root checks still run
    return records, errors


def verify_files(
    trace: str | Path,
    log_pubkey: str | Path,
    agent_pubkey: str | Path,
    witness_pubkeys: list[str | Path],
    witnessed_sths: str | Path,
) -> dict[str, Any]:
    records, errors = load_trace(trace)
    sths = json.loads(Path(witnessed_sths).read_text())
    if not isinstance(sths, list):
        raise ValueError("witnessed STH file must be a JSON array")
    return run_checks(
        records, errors, load_public_key(log_pubkey), load_public_key(agent_pubkey),
        [load_public_key(p) for p in witness_pubkeys], sths,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify a TraceLock trace.")
    ap.add_argument("--trace", required=True)
    ap.add_argument("--log-pubkey", required=True)
    ap.add_argument("--agent-pubkey", required=True)
    ap.add_argument("--witness-pubkey", action="append", required=True)
    ap.add_argument("--witnessed-sths", required=True)
    ap.add_argument("--out", help="also write the JSON result here")
    args = ap.parse_args(argv)
    try:
        result = verify_files(args.trace, args.log_pubkey, args.agent_pubkey,
                              args.witness_pubkey, args.witnessed_sths)
    except (OSError, ValueError) as exc:
        print(json.dumps({"overall": "ERROR", "error": str(exc)}), file=sys.stderr)
        return 2
    text = json.dumps(result, indent=1)
    if args.out:
        Path(args.out).write_text(text)
    print(text)
    return 0 if result["overall"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
