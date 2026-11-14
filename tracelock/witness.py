"""Witness: cosigns signed tree heads (STHs) after checking consistency.

A witness has its OWN key and its OWN data directory. It keeps the last STH it
cosigned and only cosigns a new STH if (1) the log's signature is valid and
(2) a consistency proof links the previous witnessed tree to the new one.
Anything else is rejected and, for equivocation, logged as evidence.

Modes
-----
* HTTP service:  ``python -m tracelock.witness serve --data-dir D --log-pubkey K``
* File witness:  ``python -m tracelock.witness cosign --data-dir D --log-pubkey K --sth F``
  (writes one JSON file per cosigned STH into D, which may be a separate git repo)

Storage layout (data_dir): ``witness.key``, ``witness.pub``, ``sth-<size>-<root>.json``
(one file per witnessed STH, git-friendly) and ``equivocation.log`` (JSONL).

A same-machine witness is a demo, not real independence.
"""
from __future__ import annotations

import argparse
import json
import re
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_json
from .merkle import verify_consistency
from .signing import (
    generate_private_key, key_id, load_private_key, load_public_key, public_key_hex,
    save_private_key, save_public_key, sign, verify,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class WitnessError(Exception):
    """Submission rejected. ``status`` is the HTTP status the service returns."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class Witness:
    def __init__(
        self,
        data_dir: str | Path,
        log_public_key: Ed25519PublicKey,
        key: Ed25519PrivateKey | None = None,
        clock: Callable[[], int] = time.time_ns,
    ) -> None:
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._log_pub = log_public_key
        self.log_id = key_id(log_public_key)
        self._clock = clock
        self._lock = threading.Lock()
        key_path = self.dir / "witness.key"
        if key is not None:
            self._key = key
            if not key_path.exists():
                save_private_key(key, key_path)
        elif key_path.exists():
            self._key = load_private_key(key_path)
        else:
            self._key = generate_private_key()
            save_private_key(self._key, key_path)
        save_public_key(self._key.public_key(), self.dir / "witness.pub")
        self.witness_id = key_id(self._key.public_key())
        self._chain: list[dict[str, Any]] = self._load_chain()

    # -- storage -----------------------------------------------------------

    def _load_chain(self) -> list[dict[str, Any]]:
        entries = [json.loads(p.read_text()) for p in self.dir.glob("sth-*.json")]
        return sorted(entries, key=lambda e: e["tree_size"])

    def sths(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._chain)

    def export(self, path: str | Path) -> int:
        """Write the witnessed STH file (JSON array) consumed by the verifier."""
        entries = self.sths()
        Path(path).write_text(json.dumps(entries, indent=1, sort_keys=True))
        return len(entries)

    def _log_evidence(self, reason: str, submitted: dict, proof: list[str]) -> None:
        record = {
            "time_ns": self._clock(),
            "reason": reason,
            "last_witnessed": self._chain[-1] if self._chain else None,
            "submitted": submitted,
            "consistency_proof": proof,
        }
        with open(self.dir / "equivocation.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")

    # -- core logic --------------------------------------------------------

    def submit(self, sth: dict[str, Any], proof_hex: list[str]) -> dict[str, Any]:
        """Validate and cosign. Returns the witnessed STH entry or raises WitnessError."""
        try:
            size, root = sth["tree_size"], sth["root_hash"]
            ts, log_id, sig = sth["timestamp_ns"], sth["log_id"], bytes.fromhex(sth["signature"])
            if not (isinstance(size, int) and not isinstance(size, bool) and size >= 0):
                raise ValueError("tree_size")
            if not (isinstance(root, str) and _HEX64.match(root)):
                raise ValueError("root_hash")
            if not isinstance(ts, int) or not isinstance(log_id, str):
                raise ValueError("timestamp_ns/log_id")
            proof = [bytes.fromhex(p) for p in proof_hex]
        except (KeyError, ValueError, TypeError) as exc:
            raise WitnessError(400, f"malformed submission: {exc!r}") from None
        fields = {"tree_size": size, "root_hash": root, "timestamp_ns": ts, "log_id": log_id}
        submitted = {**fields, "signature": sig.hex()}

        if log_id != self.log_id or not verify(self._log_pub, canonical_json(fields), sig):
            raise WitnessError(403, "invalid log signature or unknown log_id")

        with self._lock:
            last = self._chain[-1] if self._chain else None
            if last is not None:
                if size < last["tree_size"]:
                    self._log_evidence("rollback: tree smaller than last witnessed", submitted, proof_hex)
                    raise WitnessError(409, "tree_size is smaller than last witnessed STH")
                if size == last["tree_size"]:
                    if root == last["root_hash"]:
                        return last  # idempotent resubmission
                    self._log_evidence("equivocation: different root at same size", submitted, proof_hex)
                    raise WitnessError(409, "different root_hash at an already witnessed tree_size")
            prev_size = last["tree_size"] if last else 0
            prev_root = bytes.fromhex(last["root_hash"]) if last else None
            if last is None:
                # Trust on first use: nothing earlier to be consistent with.
                if proof:
                    raise WitnessError(400, "first STH must carry an empty consistency proof")
            elif not verify_consistency(prev_size, size, prev_root, bytes.fromhex(root), proof):
                self._log_evidence("inconsistent: consistency proof failed", submitted, proof_hex)
                raise WitnessError(409, "consistency proof from last witnessed STH failed")

            entry = {
                **fields,
                "signature": sig.hex(),
                "witness_id": self.witness_id,
                "witness_signature": sign(self._key, canonical_json(fields)).hex(),
                # Stored so an auditor can re-check the witness's chain without the log.
                "previous_tree_size": prev_size,
                "consistency_proof": list(proof_hex),
            }
            (self.dir / f"sth-{size:012d}-{root[:16]}.json").write_text(
                json.dumps(entry, sort_keys=True)
            )
            self._chain.append(entry)
            return entry


# -- HTTP service ----------------------------------------------------------


def make_server(witness: Witness, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    """POST /sth {"sth": {...incl. signature}, "consistency_proof": [hex,...]}; GET /sths."""

    class Handler(BaseHTTPRequestHandler):
        def _reply(self, status: int, body: Any) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/sths":
                self._reply(200, witness.sths())
            else:
                self._reply(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/sth":
                return self._reply(404, {"error": "not found"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length))
                sth, proof = body["sth"], body.get("consistency_proof", [])
                if not isinstance(sth, dict) or not isinstance(proof, list):
                    raise TypeError("sth must be an object and consistency_proof a list")
            except (ValueError, KeyError, TypeError) as exc:
                return self._reply(400, {"error": f"malformed request: {exc!r}"})
            try:
                self._reply(200, witness.submit(sth, proof))
            except WitnessError as exc:
                self._reply(exc.status, {"error": exc.message})

        def log_message(self, *args: Any) -> None:  # keep stdout quiet
            pass

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def serve_in_thread(server: ThreadingHTTPServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


def server_url(server: ThreadingHTTPServer) -> str:
    host, port = server.server_address[:2]
    return f"http://{host}:{port}"


# -- client helper used by the ledger -----------------------------------------


class WitnessClient:
    """Submits STHs to a witness. Use ``ledger.sth_hook = client.submit``.

    ``proof_fn(old_size, new_size)`` returns the log's consistency proof (e.g.
    ``ledger.consistency_proof``). The client remembers the last size the witness
    accepted (single-writer assumption) and asks the witness only once.
    """

    def __init__(
        self,
        base_url: str,
        proof_fn: Callable[[int, int], list[bytes]],
        timeout: float = 5.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._proof_fn = proof_fn
        self._timeout = timeout
        self._last_size: int | None = None

    def _request(self, req: urllib.request.Request) -> Any:
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            try:
                message = json.loads(exc.read()).get("error", "")
            except ValueError:
                message = ""
            raise WitnessError(exc.code, message) from None

    def submit(self, sth: Any) -> dict[str, Any]:
        """``sth``: a SignedTreeHead (or its JSON dict). Returns the witnessed STH."""
        sth_dict = sth.to_json_dict() if hasattr(sth, "to_json_dict") else dict(sth)
        if self._last_size is None:
            known = self._request(urllib.request.Request(self.base_url + "/sths"))
            self._last_size = max((e["tree_size"] for e in known), default=0)
        size = sth_dict["tree_size"]
        proof = [p.hex() for p in self._proof_fn(self._last_size, size)] if size > self._last_size else []
        body = json.dumps({"sth": sth_dict, "consistency_proof": proof}).encode()
        req = urllib.request.Request(
            self.base_url + "/sth", data=body, headers={"Content-Type": "application/json"}
        )
        entry = self._request(req)
        self._last_size = max(self._last_size, size)
        return entry


# -- file witness ------------------------------------------------------------


def cosign_file(
    data_dir: str | Path,
    log_pubkey_path: str | Path,
    sth_path: str | Path,
    proof_path: str | Path | None = None,
) -> dict[str, Any]:
    """Cosign one STH (JSON file) and write it into ``data_dir`` (maybe a git repo)."""
    witness = Witness(data_dir, load_public_key(log_pubkey_path))
    sth = json.loads(Path(sth_path).read_text())
    proof = json.loads(Path(proof_path).read_text()) if proof_path else []
    return witness.submit(sth, proof)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tracelock.witness")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("serve", "cosign", "export"):
        p = sub.add_parser(name)
        p.add_argument("--data-dir", required=True)
        if name != "export":
            p.add_argument("--log-pubkey", required=True)
    sub.choices["serve"].add_argument("--host", default="127.0.0.1")
    sub.choices["serve"].add_argument("--port", type=int, default=8800)
    sub.choices["cosign"].add_argument("--sth", required=True, help="STH JSON file")
    sub.choices["cosign"].add_argument("--proof", help="JSON list of hex proof nodes")
    sub.choices["export"].add_argument("--out", required=True)
    args = ap.parse_args(argv)

    if args.cmd == "export":
        # Reads stored files only; the log key is not needed to export.
        entries = sorted(
            (json.loads(p.read_text()) for p in Path(args.data_dir).glob("sth-*.json")),
            key=lambda e: e["tree_size"],
        )
        Path(args.out).write_text(json.dumps(entries, indent=1, sort_keys=True))
        print(f"exported {len(entries)} witnessed STHs to {args.out}")
        return 0
    if args.cmd == "cosign":
        try:
            entry = cosign_file(args.data_dir, args.log_pubkey, args.sth, args.proof)
        except WitnessError as exc:
            print(f"REJECTED ({exc.status}): {exc.message}")
            return 1
        print(json.dumps(entry, indent=1))
        return 0
    witness = Witness(args.data_dir, load_public_key(args.log_pubkey))
    server = make_server(witness, args.host, args.port)
    print(f"witness {witness.witness_id} listening on {server_url(server)}", flush=True)
    print(f"witness public key (hex): {public_key_hex(witness._key.public_key())}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
