from trezor.crypto.curve import secp256k1
from trezor.crypto.hashlib import sha3_256
from trezor.messages import EthereumTxRequest
from trezor.utils import HashWriter
from trezor.wire import DataError

from apps.ethereum.helpers import (
    address_from_bytes,
    format_ethereum_amount,
    get_fee_items_regular,
)
from apps.ethereum.layout import require_confirm_other_data, require_confirm_tx
from apps.ethereum.sign_tx import send_request_chunk

from .parser import is_valid_quai_address, parse_protobuf_tx


async def _collect_payload(msg) -> bytes:
    """Collect the full protobuf payload from the host."""
    data_total = msg.data_length  # local_cache_attribute
    if data_total <= 0:
        raise DataError("Missing protobuf payload")
    if not msg.data_initial_chunk:
        raise DataError("Initial chunk missing")
    if len(msg.data_initial_chunk) > data_total:
        raise DataError("Invalid initial chunk size")
    if data_total > 16_000_000:
        raise DataError("Payload too large")

    payload = bytearray()
    payload += msg.data_initial_chunk
    data_left = data_total - len(msg.data_initial_chunk)
    while data_left > 0:
        ack = await send_request_chunk(data_left)
        payload += ack.data_chunk
        data_left -= len(ack.data_chunk)

    return bytes(payload)


async def sign_quai_tx(msg, keychain, defs):
    """Parse Quai protobuf tx, enforce address rules, clear-sign, hash, and sign."""
    from apps.common import paths

    await paths.validate_path(keychain, msg.address_n)
    payload = await _collect_payload(msg)

    try:
        tx = parse_protobuf_tx(payload)
    except ValueError as e:
        raise DataError(f"Invalid Quai tx: {e}")

    # Chain-id must match network
    if tx.chain_id != defs.network.chain_id:
        raise DataError("Quai chain_id mismatch")

    # Enforce address rule on sender
    node = keychain.derive(msg.address_n)
    sender = node.ethereum_pubkeyhash()
    if not is_valid_quai_address(sender):
        raise DataError("Sender address violates Quai address rule")

    # Enforce address rule on recipient if present
    recipient_bytes = tx.to if tx.to else b""
    if recipient_bytes:
        if len(recipient_bytes) != 20:
            raise DataError("Invalid Quai recipient length")
        if not is_valid_quai_address(recipient_bytes):
            raise DataError("Recipient address violates Quai address rule")

    # Prepare clear-sign data
    gas_price = tx.gas_price or 0
    gas_limit = tx.gas or 0
    maximum_fee = format_ethereum_amount(
        gas_price * gas_limit, None, defs.network
    )
    fee_items = get_fee_items_regular(gas_price, gas_limit, defs.network)
    recipient_str = address_from_bytes(recipient_bytes, defs.network) if recipient_bytes else None
    is_contract_interaction = bool(tx.data)

    await require_confirm_tx(
        recipient_str,
        tx.value or 0,
        msg.address_n,
        maximum_fee,
        fee_items,
        defs.network,
        None,
        is_contract_interaction,
        chunkify=False,
    )

    if tx.data:
        await require_confirm_other_data(tx.data, len(tx.data))

    # Surface access list details, if any
    if tx.access_list:
        # Build a short summary string for display (count entries/keys)
        entry_count = len(tx.access_list)
        key_count = sum(len(t.storage_keys) for t in tx.access_list)
        # include first tuple address for context if available
        preview_parts = [f"AccessList {entry_count} entries / {key_count} keys"]
        first = tx.access_list[0]
        if first.address:
            preview_parts.append(f"addr {address_from_bytes(first.address, defs.network)}")
        await require_confirm_other_data(" | ".join(preview_parts).encode(), 0)

    # Hash protobuf envelope directly
    sha = HashWriter(sha3_256(keccak=True))
    sha.extend(payload)
    digest = sha.get_digest()

    # Hash preview (first 8 hex chars)
    await require_confirm_other_data(
        f"Hash {digest.hex()[:8]}…".encode(), len(digest)
    )

    signature = secp256k1.sign(
        node.private_key(), digest, False, secp256k1.CANONICAL_SIG_ETHEREUM
    )

    resp = EthereumTxRequest()
    # EIP-155 style v: base 27 -> + chain_id*2 + 8
    resp.signature_v = signature[0] + 2 * tx.chain_id + 8
    resp.signature_r = signature[1:33]
    resp.signature_s = signature[33:]
    return resp
