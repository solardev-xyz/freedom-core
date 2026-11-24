'use strict';

// vectors/swarm.json and swarm-grammar.json, built in a worker thread of
// generate.js (design 0015, SWM-1): the swarm vectors patch global fetch,
// Date, WebSocket and the module loader while they run, which a thread of
// their own keeps from the other builders, and they run beside them.

const fs = require('node:fs');
const { workerData, parentPort } = require('node:worker_threads');
const { buildSwarm } = require('./swarm');

(async () => {
  const keys = JSON.parse(fs.readFileSync(workerData.keysPath, 'utf8'));
  const dwebVerify = JSON.parse(fs.readFileSync(workerData.dwebVerifyPath, 'utf8'));
  const { swarm, grammar } = await buildSwarm(workerData.checkout, workerData.meta, keys, dwebVerify);
  parentPort.postMessage({ swarm, grammar });
})().catch((error) => {
  parentPort.postMessage({ error: error.stack || String(error) });
});
