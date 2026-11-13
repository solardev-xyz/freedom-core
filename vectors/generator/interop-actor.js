'use strict';

// A process of the profile reference's own, for interop.test.js: it loads
// the profiles reference's profile-catalog.js (with proper-lockfile from the
// main reference's install, as profiles.js does) and acts on one app root.
//
//   node interop-actor.js hold <appRoot> <marker>
//     Holds the catalog's write lock with the reference's
//     withCatalogWriteLockAsync, so proper-lockfile refreshes its mtime;
//     writes <marker> once it has it, and lets go when stdin closes. A lock
//     compromised meanwhile throws, as the reference's onCompromised does,
//     and the process fails.
//   node interop-actor.js try <appRoot> <displayName>
//     One createProfile, as the profile manager calls it: prints
//     {"created": id} or {"error": code, "message": …}.
//   node interop-actor.js writer <appRoot> <prefix> <count>
//     <count> times: createProfile, then renameProfile of the record made,
//     each tried again while the lock is busy (ELOCKED). One JSON line per
//     change: {"created": id} and {"renamed": id, "displayName": name}, and
//     {"busy": n} at the end.
//
// The references are FREEDOM_BROWSER_APPROVALS_CHECKOUT (the profile
// modules) and FREEDOM_BROWSER_CHECKOUT (proper-lockfile).

const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

function loadCatalog() {
  const checkout = process.env.FREEDOM_BROWSER_APPROVALS_CHECKOUT;
  const mainCheckout = process.env.FREEDOM_BROWSER_CHECKOUT;
  const mainRequire = Module.createRequire(path.join(mainCheckout, 'package.json'));
  const lockfilePath = mainRequire.resolve('proper-lockfile');
  const original = Module._resolveFilename;
  Module._resolveFilename = function resolve(request, parent, ...rest) {
    if (request === 'proper-lockfile') return lockfilePath;
    return original.call(this, request, parent, ...rest);
  };
  try {
    return require(path.join(checkout, 'src/main/profile-catalog.js'));
  } finally {
    Module._resolveFilename = original;
  }
}

function print(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function sleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** `fn()`, tried again while the catalog is busy; how many times it was. */
function retrying(fn, counter) {
  for (;;) {
    try {
      return fn();
    } catch (error) {
      if (error?.code !== 'ELOCKED') throw error;
      counter.busy += 1;
      sleep(20);
    }
  }
}

async function main() {
  const [command, appRoot, ...rest] = process.argv.slice(2);
  const catalog = loadCatalog();
  if (command === 'hold') {
    const [marker] = rest;
    await catalog.withCatalogWriteLockAsync(appRoot, async () => {
      fs.writeFileSync(marker, 'held');
      await new Promise((resolve) => {
        process.stdin.on('end', resolve);
        process.stdin.resume();
      });
    });
    print({ released: true });
  } else if (command === 'try') {
    const [displayName] = rest;
    try {
      const { record } = catalog.createProfile(appRoot, { displayName });
      print({ created: record.id });
    } catch (error) {
      print({ error: error.code || 'error', message: error.message });
    }
  } else if (command === 'writer') {
    const [prefix, count] = rest;
    const counter = { busy: 0 };
    for (let i = 0; i < Number(count); i += 1) {
      const { record } = retrying(
        () => catalog.createProfile(appRoot, { displayName: `${prefix} ${i}` }),
        counter,
      );
      print({ created: record.id });
      const displayName = `${prefix} ${i} renamed`;
      retrying(() => catalog.renameProfile(appRoot, record.id, displayName), counter);
      print({ renamed: record.id, displayName });
    }
    print({ busy: counter.busy });
  } else {
    throw new Error(`unknown command ${command}`);
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exit(1);
});
