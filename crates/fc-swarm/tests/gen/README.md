# fc-swarm's write-side answers

`generate.js` computes `../data/write-side.json`, the known answers `../write_side.rs` holds fc-swarm's write side to (design 0015, SWM-2). The oracle is `@ethersphere/bee-js` 13.2.0 and its `@ethersphere/core-sdk` 0.2.2, exactly: the versions freedom-browser's `integration/rust-core` lockfile pins. The bee-js tarball's integrity is `sha512-GAl6xkAWwPvy2sxUkzWpaF3JULtOvZ3S1U3JwL5S24sYFjPoGbbsqdUz2TVQxoTMLHx1BRmLGbIExtMs9pl6Ag==`, core-sdk's `sha512-hfnjPlJbo+LKL34iTeUUVPc8mArMPkFhuKInbTqlwpNlpljeODbMNS3G39kDQHaMZi7zanMDGoD5INTjvokgyg==`. The 13.1.0 that freedom-browser's `main` installs differs, and the generator refuses it.

**No answer is computed by the generator itself.** It calls the reference and records what it gets:

| Section | What the reference does |
|---|---|
| `trees` | core-sdk's `ChunkSplitter` over seeded data, appended in 1,000-byte pieces: the root chunk, and every chunk's address, span and unpadded payload (as a digest over the chunks sorted by address), from its `onBatch` and `finalize` |
| `bodies` (`tar`) | bee-js's `bee.collection.upload`, called as freedom-browser's `publishCollection` calls it, its `POST /bzz` body taken by a recording fake node, with `Date` fixed for the headers' modification time |
| `bodies` (`soc`) | core-sdk's `makeContentAddressedChunk(payload, span).toSingleOwnerChunk(identifier, key)`: the signature, owner, address and `identifier ‖ signature ‖ span ‖ payload` |
| `feeds` | `Topic.fromString`, bee-js's `makeFeedIdentifier`, and bee-js's feed writer (`upload`, `uploadPayload`) against the fake node: every request, and the `POST /soc` path, signature and body. For a payload over one chunk the fake node answers `POST /bytes` with ChunkSplitter's root and serves that root from `GET /chunks` as a node stores it, `span ‖ references` |
| `gsoc` | bee-js's `bee.messaging.gsocMine`: the signer's index, key, owner and SOC address, or its error |

Seeded data is `content(seed, n)`: SHA-256(seed ‖ u64_be(i)) for i = 0, 1, …, concatenated and cut to n bytes, the function fc-dweb's tests use. A case's data is `{ "seed", "length" }` or `{ "utf8" }`. The SOC and feed keys are public test keys: never fund them.

**Deviations** are marked `deviation`, with bee-js's own answer under `reference` instead of `body`. There is one, `tar-paths` (design 0015, F-3): bee-js measures a tar path in UTF-16 units and writes it into fields counted in bytes, so a name of at most 100 units and more than 100 UTF-8 bytes comes out cut. fc-swarm counts bytes and keeps the name: `write_side.rs` checks that its tar differs from bee-js's, reads back every whole path, and, for the design's own case (64 characters, 124 bytes), that it is bee-js's archive behind a GNU long-link entry.

`write_side.rs` also checks the chunker against Bee's own references in `vectors/dweb-verify.json` (design 0009's cross-check with Bee's pipeline), among them the 524,289- and 67,108,865-byte trees where a lone reference is carried up.

## Running it

The extracted packages are untrusted data: install them without scripts, and run the generator with `node` from outside their directory, naming the `node_modules` that holds them.

```sh
# Any install of bee-js 13.2.0 with its dependencies, for example:
mkdir /tmp/swm2-ref && cd /tmp/swm2-ref
npm install --ignore-scripts --no-save @ethersphere/bee-js@13.2.0
cd -

node crates/fc-swarm/tests/gen/generate.js check --node-modules /tmp/swm2-ref/node_modules
node crates/fc-swarm/tests/gen/generate.js generate --node-modules /tmp/swm2-ref/node_modules
```

CI's vectors job runs `check` against the Radicle reference's install (`npm ci --ignore-scripts` of freedom-browser at `RADICLE_REFERENCE_COMMIT`), whose lockfile pins bee-js 13.2.0 and core-sdk 0.2.2 at the integrity above. Both modes refuse any other version of either, and `meta.files` records the digests of the reference files the answers rest on, so `check` also fails on a changed install. `check` regenerates everything (about a minute: the GSOC searches to the cap take most of it) and fails unless the result equals the committed file byte for byte.

SWM-1's `vectors/swarm.json` takes over the `trees`, `bodies`, `feeds` and `gsoc` cases once it exists.
