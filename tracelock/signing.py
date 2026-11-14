"""Ed25519 key handling, signing and verification (via ``cryptography``).

Keys can be stored as raw hex (64 hex chars) or PEM. Loading auto-detects.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def sign(key: Ed25519PrivateKey, message: bytes) -> bytes:
    return key.sign(message)


def verify(pub: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    """True iff ``signature`` is a valid Ed25519 signature of ``message``."""
    try:
        pub.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def public_key_hex(pub: Ed25519PublicKey) -> str:
    return pub.public_bytes(*_RAW).hex()


def private_key_hex(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()


def public_key_from_hex(h: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(h.strip()))


def key_id(pub: Ed25519PublicKey) -> str:
    """Stable identifier: SHA-256 of the raw public key (as in RFC 6962 LogID)."""
    return hashlib.sha256(pub.public_bytes(*_RAW)).hexdigest()


def save_private_key(key: Ed25519PrivateKey, path: str | Path, fmt: str = "hex") -> None:
    """Write a private key with owner-only permissions. fmt: 'hex' or 'pem'."""
    if fmt == "hex":
        data = (private_key_hex(key) + "\n").encode()
    elif fmt == "pem":
        data = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    else:
        raise ValueError("fmt must be 'hex' or 'pem'")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def save_public_key(pub: Ed25519PublicKey, path: str | Path, fmt: str = "hex") -> None:
    if fmt == "hex":
        data = (public_key_hex(pub) + "\n").encode()
    elif fmt == "pem":
        data = pub.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:
        raise ValueError("fmt must be 'hex' or 'pem'")
    Path(path).write_bytes(data)


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    raw = Path(path).read_bytes()
    if raw.lstrip().startswith(b"-----BEGIN"):
        key = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("PEM file is not an Ed25519 private key")
        return key
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw.decode().strip()))


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    raw = Path(path).read_bytes()
    if raw.lstrip().startswith(b"-----BEGIN"):
        key = serialization.load_pem_public_key(raw)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("PEM file is not an Ed25519 public key")
        return key
    return public_key_from_hex(raw.decode())
