"""
Quai protobuf transaction parsing (Python-side skeleton).

The Ledger reference uses a protobuf envelope with the following fields:
  optional uint64 type = 1;                // QuaiTxType = 0
  optional bytes to = 2;                   // 20-byte address
  optional uint64 nonce = 3;
  optional bytes value = 4;                // big-endian int
  optional uint64 gas = 5;
  optional bytes data = 6;
  optional bytes chain_id = 7;             // big-endian int
  optional bytes gas_price = 8;            // big-endian int
  optional ProtoAccessList access_list = 9;
  optional bytes v = 10;
  optional bytes r = 11;
  optional bytes s = 12;
  // additional fields (hashes, etx metadata) currently ignored for signing

For firmware we need a streaming parser over the protobuf wire format (varints,
length-delimited fields) to avoid large allocations. This module provides a
tiny Python-side skeleton to guide the implementation; the actual parser must
be implemented in the firmware runtime (MicroPython/C) to be callable from the
signing path.
"""

from typing import Optional


class QuaiTx:
    """Parsed Quai transaction fields relevant for signing."""

    def __init__(self) -> None:
        self.chain_id: Optional[int] = None
        self.nonce: Optional[int] = None
        self.gas_price: Optional[int] = None
        self.gas: Optional[int] = None
        self.to: Optional[bytes] = None
        self.value: Optional[int] = None
        self.data: bytes = b""
        self.access_list: list[AccessTuple] = []
        self.v: Optional[int] = None
        self.r: Optional[int] = None
        self.s: Optional[int] = None


class AccessTuple:
    """Single access list tuple."""

    def __init__(self, address: bytes, storage_keys: list[bytes]) -> None:
        self.address = address
        self.storage_keys = storage_keys


def parse_protobuf_tx(_payload: bytes) -> QuaiTx:
    """
    Streaming parse of a Quai protobuf transaction.

    - Iterates over protobuf fields (varint tag/wire type).
    - Decodes required fields (chain_id, nonce, gas_price, gas, data, value, to).
    - Rejects transactions that provide v/r/s (device must set signature).
    - Enforces size limits on data/access list to avoid abuse.
    - Raises ValueError on malformed or missing-required fields.
    """
    # Helper functions kept small and self-contained; firmware should mirror them
    WIRE_VARINT = 0
    WIRE_LEN = 2

    def read_varint(buf: bytes, idx: int) -> tuple[int, int]:
        shift = 0
        result = 0
        while True:
            if idx >= len(buf):
                raise ValueError("Unexpected end of buffer while reading varint")
            b = buf[idx]
            idx += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result, idx
            shift += 7
            if shift > 63:
                raise ValueError("Varint too long")

    def read_len(buf: bytes, idx: int) -> tuple[bytes, int]:
        length, idx = read_varint(buf, idx)
        end = idx + length
        if end > len(buf):
            raise ValueError("Length-delimited field exceeds buffer")
        return buf[idx:end], end

    def bytes_to_int(b: bytes) -> int:
        if len(b) == 0:
            return 0
        return int.from_bytes(b, "big")

    tx = QuaiTx()
    idx = 0
    data_limit = 200_000  # bytes
    access_limit = 200_000  # bytes
    max_access_tuples = 16
    max_storage_keys = 64
    max_storage_key_size = 32

    while idx < len(_payload):
        key, idx = read_varint(_payload, idx)
        field_num = key >> 3
        wire_type = key & 0x07

        if wire_type == WIRE_VARINT:
            val, idx = read_varint(_payload, idx)
            if field_num == 1:  # type
                if val != 0:
                    raise ValueError("Unsupported Quai tx type")
            elif field_num == 3:  # nonce
                tx.nonce = val
            elif field_num == 5:  # gas
                tx.gas = val
            else:
                # ignore unknown varints
                pass
        elif wire_type == WIRE_LEN:
            raw, idx = read_len(_payload, idx)
            if field_num == 2:  # to
                tx.to = raw if raw else None
            elif field_num == 4:  # value
                tx.value = bytes_to_int(raw)
            elif field_num == 6:  # data
                if len(raw) > data_limit:
                    raise ValueError("Data field too large")
                tx.data = raw
            elif field_num == 7:  # chain_id
                tx.chain_id = bytes_to_int(raw)
            elif field_num == 8:  # gas_price
                tx.gas_price = bytes_to_int(raw)
            elif field_num == 9:  # access_list
                if len(raw) > access_limit:
                    raise ValueError("Access list too large")
                tx.access_list = _decode_access_list(
                    raw, max_access_tuples, max_storage_keys, max_storage_key_size
                )
            elif field_num in (10, 11, 12):  # v, r, s
                if len(raw) != 0:
                    raise ValueError("Signature fields (v/r/s) must be empty")
            else:
                # ignore other length-delimited fields
                pass
        else:
            raise ValueError("Unsupported protobuf wire type")

    # Required fields check
    if tx.chain_id is None:
        raise ValueError("Missing chain_id")
    if tx.nonce is None:
        raise ValueError("Missing nonce")
    if tx.gas_price is None:
        raise ValueError("Missing gas_price")
    if tx.gas is None:
        raise ValueError("Missing gas")
    if tx.value is None:
        raise ValueError("Missing value")
    if tx.data is None:
        raise ValueError("Missing data")

    return tx


def _decode_access_list(
    raw: bytes, max_tuples: int, max_keys: int, max_key_size: int
) -> list[AccessTuple]:
    """
    Decode ProtoAccessList:
      message ProtoAccessList { repeated ProtoAccessTuple AccessTuples = 1; }
      message ProtoAccessTuple {
        optional bytes address = 1;
        repeated bytes storage_key = 2;
      }
    """
    tuples: list[AccessTuple] = []
    idx = 0

    def read_varint(buf: bytes, idx: int) -> tuple[int, int]:
        shift = 0
        result = 0
        while True:
            if idx >= len(buf):
                raise ValueError("Unexpected end of buffer while reading varint")
            b = buf[idx]
            idx += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result, idx
            shift += 7
            if shift > 63:
                raise ValueError("Varint too long")

    def read_len(buf: bytes, idx: int) -> tuple[bytes, int]:
        length, idx = read_varint(buf, idx)
        end = idx + length
        if end > len(buf):
            raise ValueError("Length-delimited field exceeds buffer")
        return buf[idx:end], end

    while idx < len(raw):
        key, idx = read_varint(raw, idx)
        field_num = key >> 3
        wire_type = key & 0x07
        if field_num != 1 or wire_type != 2:
            # skip unknown tuple entries
            if wire_type == 0:
                _, idx = read_varint(raw, idx)
            elif wire_type == 2:
                _, idx = read_len(raw, idx)
            else:
                raise ValueError("Unsupported wire type in access list")
            continue

        tuple_bytes, idx = read_len(raw, idx)
        tup_idx = 0
        address = b""
        storage_keys: list[bytes] = []

        while tup_idx < len(tuple_bytes):
            tkey, tup_idx = read_varint(tuple_bytes, tup_idx)
            tfield = tkey >> 3
            twire = tkey & 0x07
            if twire == 0:
                _, tup_idx = read_varint(tuple_bytes, tup_idx)
            elif twire == 2:
                val, tup_idx = read_len(tuple_bytes, tup_idx)
                if tfield == 1:
                    address = val
                elif tfield == 2:
                    storage_keys.append(_decode_protohash_value(val))
            else:
                raise ValueError("Unsupported wire type in access tuple")

        if address and len(address) != 20:
            raise ValueError("Access tuple address invalid")
        if len(storage_keys) > max_keys:
            raise ValueError("Too many storage keys")
        for sk in storage_keys:
            if len(sk) > max_key_size:
                raise ValueError("Storage key too large")
        tuples.append(AccessTuple(address, storage_keys))
        if len(tuples) > max_tuples:
            raise ValueError("Too many access tuples")

    return tuples


def _decode_protohash_value(raw: bytes) -> bytes:
    """
    Decode ProtoHash { bytes value = 1; }.
    Accepts raw bytes for backward compatibility.
    """
    if not raw:
        return b""

    # Try to parse as a length-delimited message with field 1.
    idx = 0
    try:
        key, idx = _read_varint_inner(raw, idx)
    except ValueError:
        return raw  # fallback to raw
    field_num = key >> 3
    wire_type = key & 0x07
    if field_num != 1 or wire_type != 2:
        return raw  # fallback to raw
    val, idx = _read_len_inner(raw, idx)
    return val


def _read_varint_inner(buf: bytes, idx: int) -> tuple[int, int]:
    shift = 0
    result = 0
    while True:
        if idx >= len(buf):
            raise ValueError("Unexpected end of buffer while reading varint")
        b = buf[idx]
        idx += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, idx
        shift += 7
        if shift > 63:
            raise ValueError("Varint too long")


def _read_len_inner(buf: bytes, idx: int) -> tuple[bytes, int]:
    length, idx = _read_varint_inner(buf, idx)
    end = idx + length
    if end > len(buf):
        raise ValueError("Length-delimited field exceeds buffer")
    return buf[idx:end], end


def is_valid_quai_address(addr: bytes) -> bool:
    """Check Quai ledger rule: address must start with 0x00 and second byte <= 0x7f."""
    return len(addr) >= 2 and addr[0] == 0x00 and addr[1] <= 0x7F
