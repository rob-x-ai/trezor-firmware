# Quai signing behavior (current state)

- Chain_id 9 is routed to the Quai protobuf signer. It enforces the 0x00/second-byte≤0x7f address rule on sender/recipient, rejects preset v/r/s, bounds data/access lists, and hashes the protobuf envelope. Clear-sign shows recipient/amount/fee, data preview, access-list summary, and a hash preview.
- Legacy firmware now rejects chain_id 9 (no RLP signing).
- If you send an ETH/RLP tx for chain_id 9, it will fail. Host tooling must send a Quai ProtoTransaction.
- Host/Suite/Connect are not yet updated here: they still build ETH-style txs. You must adjust the host to build protobuf txs and enforce the address rule before testing end-to-end.
