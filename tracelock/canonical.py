"""Deterministic JSON serialisation and hashing.

Every byte string that is hashed or signed in TraceLock goes through
``canonical_json`` so that two parties always derive identical bytes from the
same logical object.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def _reject_floats(obj: Any, path: str = "$") -> None:
    """Raise TypeError if ``obj`` contains a float or a non-string dict key.

    Floats are banned because their textual form is not stable across
    implementations; timestamps are integer nanoseconds, anything else
    fractional must be a string.
    """
    if isinstance(obj, float):
        raise TypeError(f"floats are not allowed in canonical JSON (at {path})")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError(f"non-string key {k!r} at {path}")
            _reject_floats(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _reject_floats(v, f"{path}[{i}]")


def canonical_json(obj: Any) -> bytes:
    """Sorted keys, separators (",", ":"), UTF-8 (no \\u escapes), no floats/NaN."""
    _reject_floats(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Plain SHA-256 (no RFC 6962 prefix), hex-encoded. Used for payload hashes."""
    return hashlib.sha256(data).hexdigest()
