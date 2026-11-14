"""Record spans to a JSON fixture and replay them later (offline tests)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentelemetry.sdk.trace import SpanProcessor

from tracelock.processor import redact_obj


class RecordingProcessor(SpanProcessor):
    """Collects every finished span (attributes are redacted before they are kept)."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        pass

    def on_end(self, span: Any) -> None:
        self.records.append({
            "name": span.name,
            "span_id": f"{span.context.span_id:016x}",
            "parent_span_id": f"{span.parent.span_id:016x}" if span.parent is not None else None,
            "start_time_ns": int(span.start_time or 0),
            "attributes": redact_obj({k: (list(v) if isinstance(v, tuple) else v)
                                      for k, v in (span.attributes or {}).items()}),
        })

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


def save_fixture(path: str | Path, records: list[dict[str, Any]], note: str = "") -> None:
    Path(path).write_text(json.dumps({"note": note, "spans": records}, indent=1, sort_keys=True))


def replay_fixture(path: str | Path, tracer: Any) -> int:
    """Re-emit the recorded span tree through ``tracer`` (new ids/times). Returns span count."""
    spans = json.loads(Path(path).read_text())["spans"]
    ids = {s["span_id"] for s in spans}
    children: dict[str | None, list[dict[str, Any]]] = {}
    for s in spans:
        parent = s["parent_span_id"] if s["parent_span_id"] in ids else None
        children.setdefault(parent, []).append(s)
    for kids in children.values():
        kids.sort(key=lambda s: s["start_time_ns"])

    def emit(span: dict[str, Any]) -> None:
        with tracer.start_as_current_span(span["name"]) as sp:
            for k, v in span["attributes"].items():
                sp.set_attribute(k, v)
            for child in children.get(span["span_id"], []):
                emit(child)

    for root in children.get(None, []):
        emit(root)
    return len(spans)
