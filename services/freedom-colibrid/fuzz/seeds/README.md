Starting inputs, from COL-1's recording (`vectors/colibri.json`, case
`checkpoint-mainnet`):

- `decode_proof/checkpoint-mainnet.ssz`: the checkpoint proof the prover
  served (`vectors/fixtures/colibri/bodies/d5229934….bin`).
- `verify_proof/checkpoint-mainnet`: the same proof, 4-byte length first,
  then the `checkpointz` answer main's quorum gave its one request, the same
  way. It verifies.
