# freedom-colibrid's notices

- `c-sources.json`: what the license gate (`scripts/colibri-license-gate.py`)
  allows in each tree the C core is built from (design 0014, "Licenses").
- The texts `scripts/third-party-notices.py` copies into `THIRD-PARTY-NOTICES`
  for the C code `colibri-stateless` 3.0.3 builds into the binary, from the
  pinned fork commit (`Cargo.toml`) and the commits its CMake fetches:

| File | What | Source |
|---|---|---|
| `colibri-3.0.3-LICENSE` | Colibri's own C sources (`src/`, its generated headers, and its wrappers in `libs/evmone` and `libs/intx`) | `LICENSE` at the repository's root, solardev-xyz/colibri-stateless `freedom/pinned-3.0.3` |
| `colibri-libs-crypto-NOTICE` | `libs/crypto`: trezor-crypto's code (MIT), and Mbed TLS's `ripemd160.c` (Apache-2.0) | `libs/crypto/LICENSE`, and `ripemd160.c`'s header, at the same commit |
| `blst-0.3.13-LICENSE` | blst, BLS12-381 signatures (Apache-2.0), built by its own script | `LICENSE` at supranational/blst `52cc60d7` (v0.3.13), as `libs/blst/CMakeLists.txt` fetches it |
| `evmone-0.23.0-LICENSE` | evmone, the EVM, with EVMC (Apache-2.0) | `LICENSE` at ipsilon/evmone `2184b244` (v0.23.0), as `libs/evmone/CMakeLists.txt` fetches it |
| `intx-0.15.0-LICENSE` | intx, wide integers (Apache-2.0) | `LICENSE` at chfast/intx `0306b495` (v0.15.0), as `libs/intx/CMakeLists.txt` fetches it |

None of the fetched projects carries a `NOTICE` file. When the pin moves,
re-check each text and the commits (`NATIVE` in the script).
