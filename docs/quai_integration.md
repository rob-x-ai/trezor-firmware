# Quai integration plan (device + host)

## Scope
- Chain id 9 (mainnet), slip44 994, RPC tested: `https://rpc.quai.network/cyprus1`.
- Address rule: must start with `0x00` and second byte <= 0x7f. Reject signing otherwise.
- Tx envelope: protobuf (not RLP). Hash canonical protobuf bytes; reject preset v/r/s.

## Device work
- Add protobuf transaction parser/hasher for Quai txs (fields per Ledger ref: type, to, nonce, value, gas, data, chain_id, gas_price, access_list, optional hash fields).
- Route SIGN_TX for chain_id 9 through Quai parser; keep ETH path for others.
- Enforce address rule on derived sender and any `to`.
- Clear-sign: chain, from, to, amount (18 decimals), gas price/limit, nonce, data preview, hash preview. Abort on parse/overflow errors.
- Derivation: prefer `m/44'/994'/account'/0/index`; optionally allow 44'/60' only if explicitly enabled.
- Guard: refuse tx with signature fields set (v/r/s) from host.

## Host work (Suite/Connect)
- Use Quai RPC (quais.js) to build protobuf txs and discovery with the address rule.
- Pass protobuf bytes to device; handle chain_id 9 as Quai.
- Backend: current RPC endpoint added in `blockchain_link.json`.

## Next coding steps
- Implement protobuf schema + streaming parser in firmware (core + legacy) under a Quai-specific module.
- Wire chain_id 9 routing in SIGN_TX paths to the new parser/hasher.
- Add tests: parser vectors, address rule, signature rejection, and golden-sign cases.
