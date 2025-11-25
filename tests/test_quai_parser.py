import pytest

from core.src.apps.quai.parser import (
    AccessTuple,
    is_valid_quai_address,
    parse_protobuf_tx,
    QuaiTx,
)


def build_varint(val: int) -> bytes:
    out = bytearray()
    v = val
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def field(fnum: int, wire: int, payload: bytes) -> bytes:
    key = (fnum << 3) | wire
    out = bytearray()
    out += build_varint(key)
    if wire == 0:
        out += payload
    elif wire == 2:
        out += build_varint(len(payload))
        out += payload
    else:
        raise ValueError
    return bytes(out)


def test_address_rule():
    assert is_valid_quai_address(b"\x00\x00" + b"\x11" * 18)
    assert is_valid_quai_address(b"\x00\x7f" + b"\x22" * 18)
    assert not is_valid_quai_address(b"\x01\x00" + b"\x11" * 18)
    assert not is_valid_quai_address(b"\x00\x80" + b"\x11" * 18)
    assert not is_valid_quai_address(b"\x00")


def test_parse_minimal():
    """
    Build a minimal protobuf tx:
      type=0 (field 1, varint)
      to = 20-byte addr (field 2, len)
      nonce=1 (field 3, varint)
      value=0x01 (field 4, len)
      gas=0x5208 (21000) (field 5, varint)
      data="" (field 6, len)
      chain_id=0x9 (field 7, len)
      gas_price=0x3b9aca00 (1 gwei) (field 8, len)
    """
    payload = b"".join(
        [
            field(1, 0, build_varint(0)),
            field(2, 2, b"\x00\x00" + b"\x11" * 18),
            field(3, 0, build_varint(1)),
            field(4, 2, b"\x01"),
            field(5, 0, build_varint(21000)),
            field(6, 2, b""),
            field(7, 2, (9).to_bytes(1, "big")),
            field(8, 2, (1_000_000_000).to_bytes(4, "big")),
        ]
    )
    tx = parse_protobuf_tx(payload)
    assert isinstance(tx, QuaiTx)
    assert tx.chain_id == 9
    assert tx.nonce == 1
    assert tx.gas_price == 1_000_000_000
    assert tx.gas == 21000
    assert tx.value == 1
    assert tx.to == b"\x00\x00" + b"\x11" * 18
    assert tx.data == b""
    assert tx.access_list == []


def test_parse_reject_signature_fields():
    payload = b"".join(
        [
            field(1, 0, build_varint(0)),
            field(3, 0, build_varint(1)),
            field(4, 2, b"\x01"),
            field(5, 0, build_varint(1)),
            field(6, 2, b""),
            field(7, 2, (9).to_bytes(1, "big")),
            field(8, 2, (1).to_bytes(1, "big")),
            field(10, 2, b"\x01"),  # v set
        ]
    )
    with pytest.raises(ValueError):
        parse_protobuf_tx(payload)


def test_access_list_decode():
    """
    Build access_list:
      AccessTuples[0]: address=0x0000.., storage_key=[0xaa,0xbb]
    """
    tuple_bytes = b"".join(
        [
            field(1, 2, b"\x00" * 20),  # address
            field(2, 2, b"\xaa"),  # storage_key repeated
            field(2, 2, b"\xbb"),
        ]
    )
    access_list_raw = field(1, 2, tuple_bytes)  # AccessTuples repeated

    payload = b"".join(
        [
            field(1, 0, build_varint(0)),
            field(3, 0, build_varint(1)),
            field(4, 2, b"\x01"),
            field(5, 0, build_varint(1)),
            field(6, 2, b""),
            field(7, 2, (9).to_bytes(1, "big")),
            field(8, 2, (1).to_bytes(1, "big")),
            field(9, 2, access_list_raw),
        ]
    )
    tx = parse_protobuf_tx(payload)
    assert len(tx.access_list) == 1
    tup = tx.access_list[0]
    assert isinstance(tup, AccessTuple)
    assert tup.address == b"\x00" * 20
    assert tup.storage_keys == [b"\xaa", b"\xbb"]


def test_access_list_too_many_keys():
    tuple_bytes = b"".join(
        [field(1, 2, b"\x00" * 20)]
        + [field(2, 2, b"\x00")] * 70  # exceed limit 64
    )
    access_list_raw = field(1, 2, tuple_bytes)
    payload = b"".join(
        [
            field(1, 0, build_varint(0)),
            field(3, 0, build_varint(1)),
            field(4, 2, b"\x01"),
            field(5, 0, build_varint(1)),
            field(6, 2, b""),
            field(7, 2, (9).to_bytes(1, "big")),
            field(8, 2, (1).to_bytes(1, "big")),
            field(9, 2, access_list_raw),
        ]
    )
    with pytest.raises(ValueError):
        parse_protobuf_tx(payload)
