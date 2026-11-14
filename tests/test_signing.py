import os
import stat

import pytest

from tracelock import signing as s


def test_sign_verify_roundtrip_and_tamper():
    k = s.generate_private_key()
    sig = s.sign(k, b"msg")
    assert s.verify(k.public_key(), b"msg", sig)
    assert not s.verify(k.public_key(), b"msg2", sig)
    assert not s.verify(k.public_key(), b"msg", sig[:-1] + bytes([sig[-1] ^ 1]))
    assert not s.verify(k.public_key(), b"msg", b"short")
    assert not s.verify(s.generate_private_key().public_key(), b"msg", sig)


def test_hex_and_pem_roundtrip(tmp_path):
    k = s.generate_private_key()
    for fmt in ("hex", "pem"):
        priv, pub = tmp_path / f"k.{fmt}", tmp_path / f"k.pub.{fmt}"
        s.save_private_key(k, priv, fmt)
        s.save_public_key(k.public_key(), pub, fmt)
        k2, p2 = s.load_private_key(priv), s.load_public_key(pub)
        assert s.private_key_hex(k2) == s.private_key_hex(k)
        assert s.public_key_hex(p2) == s.public_key_hex(k.public_key())
        assert s.verify(p2, b"m", s.sign(k2, b"m"))


def test_private_key_file_permissions(tmp_path):
    k = s.generate_private_key()
    p = tmp_path / "priv"
    s.save_private_key(k, p)
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_key_id_stable_and_distinct():
    a, b = s.generate_private_key(), s.generate_private_key()
    assert s.key_id(a.public_key()) == s.key_id(a.public_key())
    assert s.key_id(a.public_key()) != s.key_id(b.public_key())
    assert len(s.key_id(a.public_key())) == 64


def test_bad_format_rejected(tmp_path):
    with pytest.raises(ValueError):
        s.save_private_key(s.generate_private_key(), tmp_path / "x", "der")
