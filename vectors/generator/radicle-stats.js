'use strict';

// Design 0008's `rad.stats` (step 4, item 14). Main at the reference asks
// for no stats: there is no health probe today (0008, "Main's side":
// "Today there's no probe"), so the result is the design's (`source:
// design`): the model below writes it from 0008's text ("Methods": the
// result; "The unit watchdog": the unit in progress and its elapsed time;
// "Main's side": readiness reads `node_alive`) and the service's constants,
// for each state of the service a case scripts, and the service's Rust
// writes the same bytes from the same state.
//
// What the reference does read:
// - `connections`: main's peer count today, `getConnections`'s `count`,
//   which reads the add-on's `status` (`{"connectedPeers": n}`), through
//   radicle-network.js's harness: `connected_peers` is that count;
// - freedom-browser's contract suite on integration/rust-core (not at the
//   pin) asks `rad.stats` for `budget.output` and holds its `used` to at
//   most its `limit`, and its `limit` to 256 MiB
//   (src/main/radicle-backend.contract.test.js, "four maximum-size results
//   with paused consumers"); every case at the service's own budget meets
//   it, and the generator checks that it does.

const assert = require('node:assert/strict');
const { loadMain, runMain } = require('./radicle-network');

const MIB = 1024 * 1024;

/** The service's constants (0008, "Pools and budgets", "The unit
 * watchdog", "Bounds"; 0007's NAT64 state). */
const CONSTANTS = {
  output_limit: 256 * MIB,
  pools: {
    read: { threads: 4, queue: 320 },
    network: { threads: 8, queue: 16 },
    write: { threads: 1, queue: 16 },
  },
  unit_limit_ms: 30000,
  nat64_prefixes: 16,
  nat64_failures: 16,
  max_result: 4096,
};

const PHASES = ['waiting', 'starting', 'running', 'down', 'stopped'];

// ---- the design's result (0008, "Methods") -----------------------------

/** `rad.stats`'s result text for `state`, as the service writes it: its
 * members in this order, compact. */
function resultText(state) {
  assert.ok(PHASES.includes(state.phase), state.phase);
  const running = state.phase === 'running';
  const pools = {};
  for (const name of ['read', 'network', 'write']) {
    const use = state.pools[name];
    const shape = CONSTANTS.pools[name];
    pools[name] = { running: use.running, queued: use.queued, threads: shape.threads, queue: shape.queue };
    // Only the write queue has online repairs.
    if (name === 'write') pools[name].repairs = use.repairs;
  }
  let nat64 = null;
  if (running && state.nat64 !== null) {
    nat64 = {
      state: state.nat64.state,
      prefixes: state.nat64.prefixes.slice(0, CONSTANTS.nat64_prefixes),
      failures: state.nat64.failures.slice(0, CONSTANTS.nat64_failures),
    };
  }
  return JSON.stringify({
    node: state.phase,
    // A thread the lock couldn't be tried on (`null`) hasn't been found
    // down by the node's watch.
    node_alive: running && state.alive !== false,
    connected_peers: running ? state.peers : null,
    unit: state.unit === null ? null : {
      kind: state.unit.kind,
      elapsed_ms: Math.floor(state.unit.elapsed_us / 1000),
      limit_ms: state.unit.limit_ms,
    },
    quarantined_count: state.quarantined,
    pools,
    budget: { output: { used: state.output.used, limit: state.output.limit } },
    network: { mode: state.mode, nat64 },
  });
}

// ---- the cases ------------------------------------------------------------

const idle = () => ({
  read: { running: 0, queued: 0, repairs: 0 },
  network: { running: 0, queued: 0, repairs: 0 },
  write: { running: 0, queued: 0, repairs: 0 },
});

/** A state: the service at the handshake, `over` changing it. */
function state(over = {}) {
  return {
    phase: 'waiting',
    alive: null,
    peers: null,
    nat64: null,
    unit: null,
    quarantined: null,
    pools: idle(),
    output: { used: 0, limit: CONSTANTS.output_limit },
    mode: 'direct',
    ...over,
  };
}

const nat64 = (name, prefixes = [], failures = []) => ({ state: name, prefixes, failures });
const known = nat64('known', ['64:ff9b::/96']);
const unit = (kind, elapsedUs, limitMs = CONSTANTS.unit_limit_ms) => ({ kind, elapsed_us: elapsedUs, limit_ms: limitMs });
const prefixes = (n) => Array.from({ length: n }, (_, i) => `2001:db8:${(i + 1).toString(16)}::/96`);

function cases() {
  const running = (over = {}) => state({ phase: 'running', alive: true, peers: 0, nat64: known, quarantined: 0, ...over });
  const out = [];
  const add = (id, about, s) => out.push({ id, about, state: s });
  add('at-the-handshake', 'before rad.identity: no node, nothing counted', state());
  add('reconciling', 'a unit of reconciliation in progress, before the node: its elapsed time in whole milliseconds',
    state({ unit: unit('cache', 1999) }));
  add('reconciled', 'rad.reconcile has counted the record', state({ quarantined: 2 }));
  add('starting', 'rad.start running: a count from before is never reported, nor NAT64',
    state({ phase: 'starting', alive: true, peers: 5, nat64: known, quarantined: 2 }));
  add('running-before-the-first-count', 'the watch hasn\'t counted the peers yet; discovery pending',
    running({ peers: null, nat64: nat64('pending') }));
  add('running', 'a running node, its peers counted, some work in the pools, some of the budget reserved',
    running({
      peers: 3,
      quarantined: 1,
      pools: {
        read: { running: 2, queued: 0, repairs: 0 },
        network: { running: 1, queued: 0, repairs: 0 },
        write: { running: 1, queued: 2, repairs: 1 },
      },
      output: { used: 3 * MIB + 17, limit: CONSTANTS.output_limit },
    }));
  add('running-held-exclusively', 'work holds the node exclusively, so its liveness isn\'t asked: the watch hasn\'t found it down',
    running({ alive: null, peers: 3 }));
  add('running-thread-ended', 'the node\'s thread ended, and the watch hasn\'t marked it down yet', running({ alive: false, peers: 3 }));
  add('down', 'the node\'s thread ended while it should run: the process is ending',
    state({ phase: 'down', alive: false, peers: 3, nat64: known, quarantined: 1 }));
  add('stopped', 'the start failed, or the connection ended', state({ phase: 'stopped', quarantined: 1 }));
  add('socks5', 'socks5 mode: no NAT64 discovery', running({ mode: 'socks5', nat64: null, peers: 2 }));
  add('quarantined-unknown', 'a count of the record that failed: unknown until the next', running({ quarantined: null }));
  add('an-online-repair-unit', 'an online repair\'s unit, past its limit as the watchdog fires; a test-hooked limit',
    running({ unit: unit('namespace-begin', 30001999), pools: { ...idle(), write: { running: 1, queued: 0, repairs: 1 } } }));
  add('a-shorter-limit', 'the unit watch\'s own limit, as a test hook sets it', running({ unit: unit('publish', 0, 1000) }));
  add('pools-full', 'every pool at its bound', running({
    pools: {
      read: { running: 4, queued: 320, repairs: 0 },
      network: { running: 8, queued: 16, repairs: 0 },
      write: { running: 1, queued: 16, repairs: 16 },
    },
  }));
  add('budget-full', 'the whole output budget reserved', running({ output: { used: CONSTANTS.output_limit, limit: CONSTANTS.output_limit } }));
  add('budget-shrunk', 'a test hook\'s budget', running({ output: { used: 4096, limit: 64 * MIB } }));
  add('nat64-unknown', 'a resolver failed: why, in order', running({ nat64: nat64('unknown', ['64:ff9b::/96'], ['timeout', 'rcode']) }));
  add('nat64-at-its-bounds', '16 prefixes and 16 failures: nothing cut',
    running({ nat64: nat64('incomplete', prefixes(16), Array(16).fill('timeout')) }));
  add('nat64-past-its-bounds', 'more than a state holds (synthetic) and 20 resolvers listed that can\'t be asked: the first 16 of each',
    running({ nat64: nat64('incomplete', prefixes(20), [...Array(8).fill('unaskable'), ...Array(12).fill('over_limit')]) }));
  // The largest: every list at its bound, the longest names, numbers at
  // JSON's safe integers.
  const big = Number.MAX_SAFE_INTEGER;
  add('largest', 'every list at its bound, the longest names and the largest numbers', state({
    phase: 'running',
    alive: true,
    peers: big,
    nat64: nat64('incomplete', Array.from({ length: 16 }, () => 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'), Array(16).fill('over_limit')),
    unit: unit('namespace-begin', big, big),
    quarantined: big,
    pools: {
      read: { running: big, queued: big, repairs: 0 },
      network: { running: big, queued: big, repairs: 0 },
      write: { running: big, queued: big, repairs: big },
    },
    output: { used: big, limit: big },
  }));
  return out;
}

async function buildRadicleStats(checkout, meta) {
  const built = cases().map((c) => ({ ...c, source: 'design', result_text: resultText(c.state) }));
  for (const c of built) {
    assert.ok(Buffer.byteLength(c.result_text) <= CONSTANTS.max_result, `${c.id}: ${c.result_text.length}`);
    const result = JSON.parse(c.result_text);
    // The contract suite's reading, at the service's own budget.
    if (c.state.output.limit === CONSTANTS.output_limit) {
      assert.equal(result.budget.output.limit, 256 * MIB, c.id);
      assert.ok(result.budget.output.used <= result.budget.output.limit, c.id);
    }
    // Readiness reads `node_alive`: only a running node is alive.
    if (result.node_alive) assert.equal(result.node, 'running', c.id);
  }
  assert.equal(new Set(built.map((c) => c.id)).size, built.length);
  for (const phase of PHASES) assert.ok(built.some((c) => c.state.phase === phase), phase);

  // `connected_peers` is the count main shows today.
  const previous = process.env.FREEDOM_RADICLE_ADDON;
  process.env.FREEDOM_RADICLE_ADDON = '/freedom-core-vectors/libradicle.node';
  const connections = [];
  try {
    const main = loadMain(checkout);
    for (const peers of [0, 3, 1000]) {
      const statusText = JSON.stringify({ connectedPeers: peers });
      const ran = await runMain(main, [{ export: 'status', args: [], text: statusText }], async () => ({
        connections: await main.manager.getConnections(),
      }));
      assert.equal(ran.connections.count, peers);
      const s = state({ phase: 'running', alive: true, peers, nat64: known, quarantined: 0 });
      const text = resultText(s);
      assert.equal(JSON.parse(text).connected_peers, ran.connections.count);
      connections.push({ id: `peers-${peers}`, status_text: statusText, main: ran, state: s, result_text: text });
    }
  } finally {
    if (previous === undefined) delete process.env.FREEDOM_RADICLE_ADDON;
    else process.env.FREEDOM_RADICLE_ADDON = previous;
  }

  return {
    meta,
    formats: {
      cases: 'The design\'s result (`source: design`) for a state of the service: `phase` (`waiting`, `starting`, `running`, `down`, `stopped`); `alive`, whether the node\'s thread still runs where the lock could be tried, else null; `peers`, the node\'s watch\'s last count, or null; `nat64`, discovery\'s stats while its lease is held (`state`, `prefixes`, `failures`), or null; `unit`, the repair unit in progress (`kind`, `elapsed_us` in microseconds, `limit_ms`), or null; `quarantined`, the record\'s last count, or null; `pools`, each pool\'s requests `running` and `queued` and the online `repairs` queued; `output`, the budget\'s `used` and `limit`; `mode`. `result_text` is the result the service writes, byte for byte.',
      connections: 'Main\'s peer count today: the add-on\'s `status` text, what the reference\'s `getConnections` returned for it (`main`, with the add-on calls it made), and `rad.stats`\'s result for a running node with that count.',
      constants: 'The service\'s bounds the result reports or holds to: the output budget, each pool\'s threads and queued places, a repair unit\'s limit, the NAT64 lists\' cuts, and the result\'s most bytes.',
    },
    constants: CONSTANTS,
    cases: built,
    connections,
  };
}

module.exports = { buildRadicleStats };
