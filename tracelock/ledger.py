"""SQLite-backed Merkle ledger with signed tree head (STH) issuance.

Design notes
------------
* ``seq`` is assigned HERE, at append time, and equals the leaf index (0-based).
  It is part of the signed leaf, so reordering or deleting events is visible.
* Two keys: the *agent/operator key* signs every leaf hash; the *log key*
  signs STHs. Both are held by the ledger because ``seq`` (inside the signed
  bytes) is only known once the ledger has assigned it.
* Appends are synchronous: the row is committed to SQLite before ``append``
  returns, so a crash cannot silently lose an acknowledged event.
* Raw payloads live in a separate table keyed by SHA-256. Leaves contain only
  hashes, so payload rows can be deleted without invalidating any proof.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonical_json, sha256_hex
from .merkle import MerkleTree, leaf_hash
from .signing import key_id, sign

log = logging.getLogger(__name__)

SESSION_END_NAME = "session_end"
SESSION_COUNT_ATTR = "tracelock.session.event_count"

# Every event carries exactly these fields (``seq`` is added by the ledger).
EVENT_FIELDS = frozenset(
    {
        "trace_id", "span_id", "parent_span_id", "name",
        "start_time_ns", "end_time_ns", "status",
        "attributes", "payload_hashes", "session_id",
    }
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq        INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL,
    leaf_data  BLOB NOT NULL,
    leaf_hash  BLOB NOT NULL,
    signature  BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS payloads (
    sha256 TEXT PRIMARY KEY,
    data   BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS sths (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tree_size    INTEGER NOT NULL,
    root_hash    TEXT NOT NULL,
    timestamp_ns INTEGER NOT NULL,
    log_id       TEXT NOT NULL,
    signature    BLOB NOT NULL
);
"""


class LedgerCorruptError(Exception):
    """Stored ledger data is inconsistent (detected while rebuilding the tree)."""


@dataclass(frozen=True)
class SignedTreeHead:
    tree_size: int
    root_hash: str  # hex
    timestamp_ns: int
    log_id: str
    signature: bytes  # log-key signature over canonical_json(sth_dict())

    def sth_dict(self) -> dict[str, Any]:
        """The signed fields."""
        return {
            "tree_size": self.tree_size,
            "root_hash": self.root_hash,
            "timestamp_ns": self.timestamp_ns,
            "log_id": self.log_id,
        }

    def signed_bytes(self) -> bytes:
        return canonical_json(self.sth_dict())

    def to_json_dict(self) -> dict[str, Any]:
        return {**self.sth_dict(), "signature": self.signature.hex()}


@dataclass(frozen=True)
class StoredEvent:
    seq: int
    session_id: str
    leaf_data: bytes
    leaf_hash: bytes
    signature: bytes

    @property
    def event(self) -> dict[str, Any]:
        return json.loads(self.leaf_data)


@dataclass(frozen=True)
class AppendResult:
    seq: int
    leaf_hash: bytes
    signature: bytes
    sth: SignedTreeHead | None  # set when this append triggered an STH


class Ledger:
    def __init__(
        self,
        db_path: str | Path,
        log_key: Ed25519PrivateKey,
        agent_key: Ed25519PrivateKey,
        sth_interval: int = 50,
        clock: Callable[[], int] = time.time_ns,
        sth_hook: Callable[[SignedTreeHead], Any] | None = None,
    ) -> None:
        """``sth_interval``: auto-issue an STH every N events (0/None disables).

        ``sth_hook`` is called synchronously with every newly issued STH (e.g. a
        WitnessClient.submit). A failing hook never breaks the append: the error
        is logged and stored in ``hook_errors`` for the caller to inspect.
        """
        self.sth_hook = sth_hook
        self.hook_errors: list[str] = []
        self._log_key = log_key
        self._agent_key = agent_key
        self.log_id = key_id(log_key.public_key())
        self.sth_interval = sth_interval or 0
        self._clock = clock
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._db.executescript(_SCHEMA)
        self._tree = MerkleTree()
        self._session_counts: dict[str, int] = {}  # excludes session_end itself
        self._ended: set[str] = set()
        self._rebuild()

    # -- startup -----------------------------------------------------------

    def _rebuild(self) -> None:
        """Rebuild the in-memory tree from stored leaves, checking basic integrity."""
        rows = self._db.execute(
            "SELECT seq, leaf_data, leaf_hash FROM events ORDER BY seq"
        )
        for i, (seq, data, stored_hash) in enumerate(rows):
            if seq != i:
                raise LedgerCorruptError(f"seq gap: expected {i}, found {seq}")
            if leaf_hash(data) != stored_hash:
                raise LedgerCorruptError(f"leaf hash mismatch at seq {seq}")
            event = json.loads(data)
            if event.get("seq") != seq:
                raise LedgerCorruptError(f"seq inside leaf differs from row at {seq}")
            self._tree.append_leaf_hash(stored_hash)
            self._note_event(event)
        for size, root in self._db.execute("SELECT tree_size, root_hash FROM sths"):
            if size > self._tree.size or self._tree.root_at(size).hex() != root:
                raise LedgerCorruptError(f"stored STH for size {size} does not match leaves")

    def _note_event(self, event: dict[str, Any]) -> None:
        sid = event["session_id"]
        if event["name"] == SESSION_END_NAME:
            self._ended.add(sid)
        else:
            self._session_counts[sid] = self._session_counts.get(sid, 0) + 1

    # -- appending ---------------------------------------------------------

    def append(self, event: dict[str, Any], payloads: Iterable[bytes] = ()) -> AppendResult:
        """Assign seq, sign, persist and add to the tree. Returns once committed.

        ``event`` must contain exactly EVENT_FIELDS (no ``seq``).
        ``payloads``: raw blobs to store (keyed by their SHA-256) alongside.
        """
        blobs = list(payloads)
        if not all(isinstance(b, bytes) for b in blobs):
            raise TypeError("payloads must be bytes")
        if "seq" in event:
            raise ValueError("seq is assigned by the ledger; do not set it on the event")
        if set(event) != EVENT_FIELDS:
            raise ValueError(f"event fields mismatch: {sorted(set(event) ^ EVENT_FIELDS)}")
        with self._lock:
            return self._append_locked(event, blobs)

    def _append_locked(self, event: dict[str, Any], blobs: list[bytes]) -> AppendResult:
        seq = self._tree.size
        full = {**event, "seq": seq}
        leaf_data = canonical_json(full)  # also rejects floats
        lh = leaf_hash(leaf_data)
        signature = sign(self._agent_key, lh)
        with self._db:  # one transaction: commit on success, roll back on error
            self._db.execute(
                "INSERT INTO events (seq, session_id, leaf_data, leaf_hash, signature)"
                " VALUES (?, ?, ?, ?, ?)",
                (seq, full["session_id"], leaf_data, lh, signature),
            )
            self._db.executemany(
                "INSERT OR IGNORE INTO payloads (sha256, data) VALUES (?, ?)",
                [(sha256_hex(b), b) for b in blobs],
            )
        # Only after the commit succeeded do we advance in-memory state.
        self._tree.append_leaf_hash(lh)
        self._note_event(full)
        due = self.sth_interval > 0 and self._tree.size % self.sth_interval == 0
        sth = self._issue_sth_locked() if due or full["name"] == SESSION_END_NAME else None
        return AppendResult(seq, lh, signature, sth)

    def end_session(self, session_id: str) -> AppendResult:
        """Append the session_end event committing to the session's event count."""
        with self._lock:
            if session_id in self._ended:
                raise ValueError(f"session {session_id!r} already ended")
            now = self._clock()
            event = {
                "trace_id": "", "span_id": "", "parent_span_id": None,
                "name": SESSION_END_NAME,
                "start_time_ns": now, "end_time_ns": now, "status": "OK",
                "attributes": {SESSION_COUNT_ATTR: self._session_counts.get(session_id, 0)},
                "payload_hashes": {"input_sha256": None, "output_sha256": None},
                "session_id": session_id,
            }
            return self._append_locked(event, [])  # always issues an STH

    # -- STHs --------------------------------------------------------------

    def issue_sth(self) -> SignedTreeHead:
        with self._lock:
            return self._issue_sth_locked()

    def _issue_sth_locked(self) -> SignedTreeHead:
        fields = {
            "tree_size": self._tree.size,
            "root_hash": self._tree.root().hex(),
            "timestamp_ns": self._clock(),
            "log_id": self.log_id,
        }
        sig = sign(self._log_key, canonical_json(fields))
        with self._db:
            self._db.execute(
                "INSERT INTO sths (tree_size, root_hash, timestamp_ns, log_id, signature)"
                " VALUES (?, ?, ?, ?, ?)",
                (*fields.values(), sig),
            )
        sth = SignedTreeHead(signature=sig, **fields)
        if self.sth_hook is not None:
            try:
                self.sth_hook(sth)
            except Exception as exc:  # witness down / rejected: record, don't lose the event
                msg = f"STH size {sth.tree_size}: {type(exc).__name__}: {exc}"
                self.hook_errors.append(msg)
                log.warning("STH hook failed: %s", msg)
        return sth

    def sths(self) -> list[SignedTreeHead]:
        with self._lock:
            rows = self._db.execute(
                "SELECT tree_size, root_hash, timestamp_ns, log_id, signature"
                " FROM sths ORDER BY id"
            ).fetchall()
        return [SignedTreeHead(*r) for r in rows]

    def latest_sth(self) -> SignedTreeHead | None:
        s = self.sths()
        return s[-1] if s else None

    # -- reads -------------------------------------------------------------

    @property
    def size(self) -> int:
        return self._tree.size

    @property
    def root(self) -> bytes:
        return self._tree.root()

    def root_at(self, size: int) -> bytes:
        return self._tree.root_at(size)

    def inclusion_proof(self, seq: int, size: int | None = None) -> list[bytes]:
        with self._lock:
            return self._tree.inclusion_proof(seq, size)

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> list[bytes]:
        with self._lock:
            return self._tree.consistency_proof(old_size, new_size)

    def get_event(self, seq: int) -> StoredEvent:
        row = self._db.execute(
            "SELECT seq, session_id, leaf_data, leaf_hash, signature FROM events WHERE seq=?",
            (seq,),
        ).fetchone()
        if row is None:
            raise KeyError(seq)
        return StoredEvent(*row)

    def iter_events(self) -> Iterator[StoredEvent]:
        cur = self._db.execute(
            "SELECT seq, session_id, leaf_data, leaf_hash, signature FROM events ORDER BY seq"
        )
        for row in cur:
            yield StoredEvent(*row)

    def get_payload(self, sha256: str) -> bytes | None:
        row = self._db.execute("SELECT data FROM payloads WHERE sha256=?", (sha256,)).fetchone()
        return row[0] if row else None

    def export_trace(self, path: str | Path, include_payloads: bool = True) -> int:
        """Write the trace as JSONL: {"event":..., "signature": hex[, "payloads": {sha256: text}]}.

        Payloads are optional; the verifier reports "payload redacted" without them.
        Returns the number of events written.
        """
        n = 0
        with open(path, "w", encoding="utf-8") as f:
            for se in self.iter_events():
                ev = se.event
                line: dict[str, Any] = {"event": ev, "signature": se.signature.hex()}
                if include_payloads:
                    found = {}
                    for h in (ev.get("payload_hashes") or {}).values():
                        data = self.get_payload(h) if h else None
                        if data is not None:
                            found[h] = data.decode("utf-8")
                    if found:
                        line["payloads"] = found
                f.write(json.dumps(line, sort_keys=True, ensure_ascii=False) + "\n")
                n += 1
        return n

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> "Ledger":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
