'use strict';

// A worker thread for vectors/swarm.json's `gsoc` (design 0015, SWM-1): runs
// bee-js's own gsocMine, from the swarm reference's install, over the cases
// it is handed, so the searches to the cap run beside the other sections.

const path = require('node:path');
const { workerData, parentPort } = require('node:worker_threads');
const { createRequire } = require('node:module');

const ref = createRequire(path.join(workerData.checkout, 'package.json'));
const beeJs = ref('@ethersphere/bee-js');
const core = ref('@ethersphere/core-sdk');
const bee = new beeJs.Bee('http://127.0.0.1:1633');

parentPort.postMessage(workerData.cases.map((c) => {
  const record = { ...c };
  try {
    const signer = bee.messaging.gsocMine(c.target, c.identifier, c.proximity);
    const owner = signer.publicKey().address();
    record.result = {
      index: Number(signer.toBigInt() - 0xb33n),
      key: signer.toHex(),
      owner: owner.toHex(),
      address: core.makeSOCAddress(new core.Identifier(c.identifier), owner).toHex(),
    };
  } catch (err) {
    record.error = String(err.message);
  }
  return record;
}));
