"""One-call integration helper: wires keys, ledger, processor and witness client.

This is convenience only; everything it does can be done by hand with the building blocks
in ``ledger.py``, ``processor.py`` and ``witness.py``. OpenTelemetry is imported lazily
inside ``setup`` so ``init_keys`` works without it.
"""
from __future__ import annotations

import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .signing import generate_private_key, load_private_key, save_private_key, save_public_key


@dataclass(frozen=True)
class KeyPaths:
    log_key: Path
    log_pub: Path
    agent_key: Path
    agent_pub: Path


@dataclass(frozen=True)
class Export:
    """Files to hand to an auditor. Witness public key(s) come from the witness operator."""

    trace: Path
    log_pub: Path
    agent_pub: Path
    witnessed_sths: Path | None  # None when no witness was configured


def init_keys(data_dir: str | Path = "tracelock_data") -> KeyPaths:
    """Create (or reuse) the log and operator key pairs under ``data_dir/keys``.

    Run this first when you need ``log.pub`` for starting a witness. Existing private keys
    are never overwritten. Private keys are written with owner-only permissions.
    """
    keys = Path(data_dir) / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    for name in ("log", "agent"):
        priv = keys / f"{name}.key"
        key = load_private_key(priv) if priv.exists() else generate_private_key()
        if not priv.exists():
            save_private_key(key, priv)
        save_public_key(key.public_key(), keys / f"{name}.pub")
    return KeyPaths(keys / "log.key", keys / "log.pub", keys / "agent.key", keys / "agent.pub")


class TraceLock:
    """Handle returned by ``setup``. Usable as a context manager."""

    def __init__(self, ledger: Any, processor: Any, provider: Any, data_dir: Path,
                 session_id: str, keys: KeyPaths, witness_url: str | None) -> None:
        self.ledger, self.processor, self.provider = ledger, processor, provider
        self.data_dir, self.session_id, self.keys = data_dir, session_id, keys
        self.witness_url = witness_url
        self._ended = False
        self._closed = False

    def tracer(self, name: str = "agent") -> Any:
        """An OpenTelemetry tracer from the provider TraceLock is attached to."""
        return self.provider.get_tracer(name)

    @property
    def witness_errors(self) -> list[str]:
        """Witness submissions that failed or were rejected. Check this: events are never lost,
        but an unwitnessed checkpoint widens the tail an attacker could truncate."""
        return list(self.ledger.hook_errors)

    def end_session(self) -> None:
        """Commit the session's event count and issue a final STH (idempotent)."""
        if not self._ended:
            self.processor.end_session()
            self._ended = True

    def export(self, out_dir: str | Path | None = None) -> Export:
        """End the session if still open, write ``trace.jsonl`` and fetch the witnessed STHs."""
        self.end_session()
        out = Path(out_dir) if out_dir else self.data_dir / "export"
        out.mkdir(parents=True, exist_ok=True)
        self.ledger.export_trace(out / "trace.jsonl")
        sths = None
        if self.witness_url:
            with urllib.request.urlopen(self.witness_url.rstrip("/") + "/sths", timeout=5) as resp:
                sths = out / "witnessed_sths.json"
                sths.write_bytes(resp.read())
        return Export(out / "trace.jsonl", self.keys.log_pub, self.keys.agent_pub, sths)

    def close(self) -> None:
        """End the session if needed and close the ledger (idempotent). The provider is left
        running because it may belong to your application."""
        if not self._closed:
            self.end_session()
            self.ledger.close()
            self._closed = True

    def __enter__(self) -> "TraceLock":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def setup(
    data_dir: str | Path = "tracelock_data",
    *,
    witness_url: str | None = None,
    session_id: str | None = None,
    sth_interval: int = 20,
    provider: Any = None,
    set_global: bool = False,
) -> TraceLock:
    """Create keys (first run), the ledger, the witness client and the span processor.

    data_dir      keys/ and ledger.db live here (reused on later runs).
    witness_url   base URL of a running witness; without it nothing is witnessed and the
                  auditor will have no anchor (the verifier fails such traces).
    session_id    defaults to a random id; one session = one ``session_end`` commitment.
    sth_interval  checkpoint every N events (also at session end). Smaller N shortens the
                  unwitnessed tail but costs more commits and witness calls.
    provider      your existing OpenTelemetry SDK ``TracerProvider``; the processor is added
                  to it. If omitted a new provider is created.
    set_global    when TraceLock creates the provider, also register it as the global one.
    """
    from opentelemetry.sdk.trace import TracerProvider

    from .ledger import Ledger
    from .processor import TraceLockSpanProcessor
    from .witness import WitnessClient

    root = Path(data_dir)
    keys = init_keys(root)
    ledger = Ledger(root / "ledger.db", load_private_key(keys.log_key),
                    load_private_key(keys.agent_key), sth_interval=sth_interval)
    if witness_url:
        ledger.sth_hook = WitnessClient(witness_url, ledger.consistency_proof).submit
    sid = session_id or f"session-{uuid.uuid4().hex[:12]}"
    processor = TraceLockSpanProcessor(ledger, sid)
    if provider is None:
        provider = TracerProvider()
        if set_global:
            from opentelemetry import trace

            trace.set_tracer_provider(provider)
    provider.add_span_processor(processor)
    return TraceLock(ledger, processor, provider, root, sid, keys, witness_url)
