# Quai integration — remaining work

## Device (firmware)
- **Golden vectors**: added a basic golden digest/signature test (tests/test_quai_parser.py) using test privkey `11..11`. Consider adding more cases or a second vector.
- **Access list UI**: currently shows a summary; optionally render per-tuple detail (address + first N storage keys).
- **Hash preview UX**: refine formatting per product design (length, placement).
- **Bounds**: review/align access list/data limits with final firmware constraints.
- **Legacy**: legacy path currently rejects chain_id 9; implement a legacy Quai protobuf signer only if needed.

## Host (Suite/Connect)
- Build Quai protobuf transactions (quais.js or equivalent), not RLP.
- Enforce address rule (0x00 prefix, second byte ≤ 0x7f) in discovery and signing.
- Point Quai network to `https://rpc.quai.network/cyprus1`.
- Add signing call to pass protobuf payload to device; update chain handling for id 9.

## Tests
- Parser negatives beyond current cases; malformed access lists, oversized fields.
- Additional end-to-end signing vectors if new fixtures are added.

## Data/fixtures needed
- Additional canonical protobuf tx payloads/signatures if more golden tests are desired. Current test uses privkey `11..11` and chain_id 9.
