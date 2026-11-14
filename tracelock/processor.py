"""OpenTelemetry SpanProcessor that records gen_ai.* spans into the ledger.

Spans end child-before-parent, so ordering is by ledger ``seq``, never by span
time. Only a small whitelist of attributes enters the signed event; prompts and
outputs are hashed (after redaction) and stored in the separate payloads table.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor

from .canonical import sha256_hex
from .ledger import Ledger

# ---------------------------------------------------------------------------
# Central configuration. gen_ai.* semantic conventions are EXPERIMENTAL and
# attribute names drift between versions. Every assumption lives in the tables
# below, so drift needs a one-place change.
# VERIFY AGAINST CURRENT DOCS: all names below (OTel GenAI semantic conventions).
# ---------------------------------------------------------------------------

# source span attribute -> key stored in the event. Earlier entries win when
# several sources map to the same target.
ATTRIBUTE_MAP: dict[str, str] = {
    "gen_ai.operation.name": "gen_ai.operation.name",
    "gen_ai.request.model": "gen_ai.request.model",
    "gen_ai.usage.input_tokens": "gen_ai.usage.input_tokens",
    "gen_ai.usage.prompt_tokens": "gen_ai.usage.input_tokens",  # older name
    "gen_ai.usage.output_tokens": "gen_ai.usage.output_tokens",
    "gen_ai.usage.completion_tokens": "gen_ai.usage.output_tokens",  # older name
    "gen_ai.tool.name": "gen_ai.tool.name",
    "gen_ai.tool.call.id": "gen_ai.tool.call.id",
}

# First key present on the span is hashed as the input / output payload.
INPUT_PAYLOAD_KEYS = (
    "tracelock.input",
    "gen_ai.input.messages",
    "gen_ai.tool.call.arguments",
    "gen_ai.prompt",
)
OUTPUT_PAYLOAD_KEYS = (
    "tracelock.output",
    "gen_ai.output.messages",
    "gen_ai.tool.call.result",
    "gen_ai.completion",
)

# Span attributes that may carry the session id (first present wins).
SESSION_ID_KEYS = ("tracelock.session_id", "gen_ai.conversation.id", "session.id")

# A span is recorded only if it carries at least one attribute with this prefix.
GENAI_PREFIX = "gen_ai."

# ---------------------------------------------------------------------------
# Redaction (applied BEFORE hashing or storing any payload)
# ---------------------------------------------------------------------------

REDACTED = "[REDACTED]"

# Environment variables whose literal values are scrubbed from any payload.
SECRET_ENV_VARS = ("GROQ_API_KEY", "OPENAI_API_KEY")

_SENSITIVE_KEY = re.compile(
    r"^(authorization|proxy-authorization|x-api-key|api[-_]?key|apikey|secret|"
    r"password|passwd|token|access[-_]?token|(groq|openai)[-_]?api[-_]?key)$",
    re.IGNORECASE,
)
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_KEY_TOKENS = [re.compile(r"\bgsk_[A-Za-z0-9]{16,}"), re.compile(r"\bsk-[A-Za-z0-9_-]{16,}")]
# `Authorization: xxx`, `"api_key": "xxx"`, `api-key=xxx` -> keep the key, hide the value.
_KEY_VALUE = re.compile(
    r"""(["']?\b(?:api[_-]?key|authorization|x-api-key)\b["']?\s*[:=]\s*["']?)[^\s"',}]+""",
    re.IGNORECASE,
)


def redact_text(text: str) -> str:
    for var in SECRET_ENV_VARS:
        env_key = os.environ.get(var, "")
        if len(env_key) >= 8:
            text = text.replace(env_key, REDACTED)
    text = _BEARER.sub(REDACTED, text)
    for pat in _KEY_TOKENS:
        text = pat.sub(REDACTED, text)
    return _KEY_VALUE.sub(lambda m: m.group(1) + REDACTED, text)


def redact_obj(obj: Any) -> Any:
    """Recursively redact strings, and values under sensitive dict keys."""
    if isinstance(obj, dict):
        return {
            k: REDACTED if isinstance(k, str) and _SENSITIVE_KEY.match(k) else redact_obj(v)
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


def payload_bytes(value: Any) -> bytes:
    """Redacted UTF-8 bytes of an attribute value; this is what gets hashed/stored."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return redact_text(value).encode("utf-8")
    return json.dumps(
        redact_obj(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Span -> Event
# ---------------------------------------------------------------------------


def _norm_attr(value: Any) -> Any:
    """Make an attribute value canonical-JSON safe (no floats, no tuples)."""
    if isinstance(value, float):
        return repr(value)  # floats are banned in canonical JSON; keep as string
    if isinstance(value, (list, tuple)):
        return [_norm_attr(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _first_present(attrs: Any, keys: tuple[str, ...]) -> Any:
    for k in keys:
        if k in attrs:
            return attrs[k]
    return None


def has_genai_attributes(span: ReadableSpan) -> bool:
    return any(str(k).startswith(GENAI_PREFIX) for k in (span.attributes or {}))


def span_to_event(
    span: ReadableSpan, default_session_id: str = "default"
) -> tuple[dict[str, Any], list[bytes]]:
    """Convert a finished span into (event without seq, payload blobs to store)."""
    attrs = span.attributes or {}

    event_attrs: dict[str, Any] = {}
    for source, target in ATTRIBUTE_MAP.items():
        if source in attrs and target not in event_attrs:
            event_attrs[target] = _norm_attr(attrs[source])

    blobs: list[bytes] = []
    hashes: dict[str, str | None] = {"input_sha256": None, "output_sha256": None}
    for field, keys in (("input_sha256", INPUT_PAYLOAD_KEYS), ("output_sha256", OUTPUT_PAYLOAD_KEYS)):
        value = _first_present(attrs, keys)
        if value is not None:
            blob = payload_bytes(value)
            hashes[field] = sha256_hex(blob)
            blobs.append(blob)

    ctx, parent = span.context, span.parent
    status = span.status.status_code.name if span.status is not None else "UNSET"
    session_id = _first_present(attrs, SESSION_ID_KEYS) or default_session_id

    event = {
        "trace_id": f"{ctx.trace_id:032x}",
        "span_id": f"{ctx.span_id:016x}",
        "parent_span_id": f"{parent.span_id:016x}" if parent is not None else None,
        "name": span.name,
        "start_time_ns": int(span.start_time or 0),
        "end_time_ns": int(span.end_time or 0),
        "status": status,
        "attributes": event_attrs,
        "payload_hashes": hashes,
        "session_id": str(session_id),
    }
    return event, blobs


class TraceLockSpanProcessor(SpanProcessor):
    """Appends each finished gen_ai.* span to the ledger (synchronously).

    Errors from the ledger propagate out of ``on_end`` (the OTel SDK logs them)
    rather than being swallowed, so a failed append is never silent.
    """

    def __init__(self, ledger: Ledger, session_id: str = "default") -> None:
        self._ledger = ledger
        self._session_id = session_id

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        pass

    def on_end(self, span: ReadableSpan) -> None:
        if not has_genai_attributes(span):
            return  # not an agent span (e.g. an HTTP client span): not recorded
        event, blobs = span_to_event(span, self._session_id)
        self._ledger.append(event, blobs)

    def end_session(self) -> None:
        """Commit the session's event count and issue an STH."""
        self._ledger.end_session(self._session_id)

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True  # appends are synchronous; nothing is buffered
