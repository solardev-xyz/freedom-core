# fc-ledger's synthetic device recordings

`synthetic-recordings.js` writes `../data/ledger-devices-synthetic/`, the recordings `../device_recordings.rs` replays against the core's Ledger machine until the real ones exist (design 0016, LDG-3; the LDG-3 plan's C1). **They are not device evidence.** Each file's `meta.synthetic` says so, and its firmware is `synthetic`. The test refuses them among the real recordings and refuses a real one without those marks among them.

They come from freedom-browser's own recorder, `scripts/ledger-record.js` (PR 13), run whole on a checkout of `integration/rust-core` against the fake node-hid (`test/helpers/fake-node-hid.js`), behind a scripted Ethereum app holding the public test phrase, with simulated hands doing what each step asks. The scripted app and the hands are copied from `scripts/ledger-record.test.js` at freedom-browser `2210097b`, because that test doesn't export them. Everything else, main's stream included, is the checkout's, loaded with `createRequire` anchored in it. There are two files: a Nano S Plus (every field step of the device session, with the reference streams of F-2's names) and a Nano S (the hash-only steps).

```sh
node crates/fc-ledger/tests/gen/synthetic-recordings.js --freedom-browser <checkout>
```

The checkout needs its packages installed. Timings and `recordedAt` differ from run to run. The replay doesn't judge timings, so a regenerated file replays the same.

**The real recordings** go in `vectors/ledger-devices/`, one file per model, named `ledger-devices-<model>.json` as the recorder suggests, copied in unchanged. Each must be the whole session the recorder plays for its model: `meta.complete`, and every step done as it asks. Nothing else goes in that directory. Once it holds a file, `device_recordings_replay` replays every file in it and CI holds the core to them. These synthetic files stay as the damage tests' material.
