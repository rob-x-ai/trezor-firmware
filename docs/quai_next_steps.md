# Quai integration — remaining work

## Device (firmware)
- **Golden vectors**: add a reproducible test that signs a known protobuf tx with a fixed test key/path, asserting digest and signature. Needs a test keypair + protobuf fixture.
- **Access list UI**: optionally render per-tuple detail (address + first N storage keys) instead of summary only.
- **Hash preview UX**: refine formatting per product design (length, placement).
- **Bounds**: review/align access list/data limits with final firmware constraints.
- **Legacy**: if legacy signing is needed, implement a Quai protobuf signer; currently guarded/rejected.

## Host (Suite/Connect)
- Build Quai protobuf transactions (quais.js or equivalent), not RLP.
- Enforce address rule (0x00 prefix, second byte ≤ 0x7f) in discovery and signing.
- Point Quai network to `https://rpc.quai.network/cyprus1`.
- Add signing call to pass protobuf payload to device; update chain handling for id 9.

## Tests
- Parser negatives beyond current cases; malformed access lists, oversized fields.
- End-to-end signing vector once test key + tx fixture are available.

## Data/fixtures needed
- Canonical protobuf tx payload for chain_id 9 with expected digest/signature.
- Fixed derivation path and test seed/key to derive the signing key consistently.
