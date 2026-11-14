import pytest

from tracelock.canonical import canonical_json, sha256_hex


def test_sorted_keys_and_compact_separators():
    assert canonical_json({"b": 1, "a": [1, 2], "c": None}) == b'{"a":[1,2],"b":1,"c":null}'


def test_insertion_order_irrelevant_and_nested():
    a = {"x": {"b": 1, "a": 2}, "y": True}
    b = {"y": True, "x": {"a": 2, "b": 1}}
    assert canonical_json(a) == canonical_json(b)


def test_utf8_not_ascii_escaped():
    assert canonical_json({"k": "é✓"}) == '{"k":"é✓"}'.encode("utf-8")


def test_floats_rejected_everywhere():
    for bad in (1.5, {"a": 0.1}, [1, [2.0]], {"a": {"b": [float("nan")]}}):
        with pytest.raises(TypeError):
            canonical_json(bad)


def test_large_ints_ok_for_nanosecond_timestamps():
    assert canonical_json({"t": 1731234567890123456}) == b'{"t":1731234567890123456}'


def test_non_string_keys_rejected():
    with pytest.raises(TypeError):
        canonical_json({1: "x"})


def test_sha256_hex_known_vector():
    assert sha256_hex(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
