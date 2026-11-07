'use strict';

// Design 0008's network operations (step 4, item 13): `rad.connect_seeds`,
// `rad.clone` and its `rad.progress` events. Main's own code at the
// reference reads every text here: the add-on is scripted, as in
// radicle-reads.js (each export main calls, its arguments, and the JSON
// text it returns, in libradicle's shapes at the service's pin: src/json.rs
// and src/error.rs), and the reference's real radicle-embedded.js,
// radicle-manager.js and radicle/seed-status.js run on them, through
// naming.js's harness: their own requires are stubbed, and no reference
// code is copied. `Date.now` counts up from a fixed instant while main
// runs, so the statuses main publishes are the same on every run.
//
// What only the service has is the design's (`source: design`): the
// progress queue (0008, "Progress": coalescing, the summary, the reserved
// terminal event, the 4 KiB envelope and how an event is cut down) and the
// service's answers (0008, "Methods" and "Errors"). The queue's model below
// follows the design's text; the service's Rust replays every case.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const { isDeepStrictEqual } = require('node:util');
const { loadWithInternals } = require('./naming');

// Where the reference looks for the add-on (radicle-reads.js).
const ADDON = '/freedom-core-vectors/libradicle.node';

const RID = 'rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5';
const NID = 'z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw';
const NID2 = 'z6MkfG5kHWh9VjcuGfC2rHwRfgnL6P3z1ijj9KzxrmwtGzLQ';
const ch = (code) => String.fromCodePoint(code);
const NUL = ch(0);
const BS = ch(0x5c);
const QUOTE = ch(0x22);
const E_ACUTE = ch(0xe9);
const ROCKET = ch(0x1f680);
const CUT = ch(0x2026);
/** Every kind of character an envelope widens: a NUL is 6 bytes in an
 * event's JSON and 7 in its envelope's, a backslash and a quote 4 each,
 * `é` 2 and the rocket 4 as UTF-8. The browser's pending contract test
 * (`progress-summary`) uses the same mix. */
const MIXED = `${NUL}${BS}${QUOTE}${E_ACUTE}${ROCKET}x`;

const text = (value) => JSON.stringify(value);
const error = (message) => text({ error: message });

// ---- libradicle's shapes ----------------------------------------------

/** `json::seed_report`: its keys, in order. */
const seedReport = (r) => text({
  attempted: r.attempted,
  connected: r.connected,
  target: r.target,
  targetReached: r.targetReached,
  elapsedMs: r.elapsedMs,
  failures: r.failures.map((f) => ({ nid: f.nid, addr: f.addr, reason: f.reason })),
});

/** `json::progress`: the variant's fields, then `phase` last (a `json!`
 * value with `preserve_order`, its phase set after). */
function progressText(p) {
  const fields = {
    resolving: () => ({ candidates: p.candidates }),
    connecting: () => ({ nid: p.nid, addr: p.addr, index: p.index, total: p.total }),
    fetching: () => ({ nid: p.nid, index: p.index, total: p.total }),
    'peer-failed': () => ({ nid: p.nid, index: p.index, total: p.total, reason: p.reason }),
    failed: () => ({ reason: p.reason }),
    done: () => ({}),
    cancelled: () => ({}),
  }[p.phase];
  assert.ok(fields, p.phase);
  return text({ ...fields(), phase: p.phase });
}

/** libradicle's `Error` Display texts, as the add-on returns them in
 * `{"error": …}` (src/error.rs), and heartwood's `RepoState` names. */
const STATES = { namespace: 'quarantined (namespace)', cache: 'quarantined (cache)', repairing: 'being repaired' };
function errorText(e) {
  switch (e.variant) {
    case 'NoSeeds': return `no seeds found for ${e.rid}`;
    case 'FetchFailed': return `fetching ${e.rid} failed: ${e.reason}`;
    case 'Timeout': return `fetching ${e.rid} timed out`;
    case 'Cancelled': return 'cancelled';
    case 'NodeThread': return `node thread: ${e.message}`;
    case 'Gated': return `${e.rid} is ${STATES[e.state]}: it can't be seeded until it opens`;
    default: throw new Error(`no variant ${e.variant}`);
  }
}

// ---- the design's progress queue (0008, "Progress") --------------------

const MAX_ENVELOPE = 4096;
const FAILURES = 8;
const REASONS = 4;
const bytes = (s) => Buffer.byteLength(s, 'utf8');
/** The envelope the connection writes for `event` about request `id`:
 * fc-protocol's `write_event`, whose key order and escaping JSON.stringify
 * shares for these values (IDs stay below 2^53). */
const envelope = (id, event) => text({ type: 'event', event: 'rad.progress', data: { id, event } });
const fits = (id, event) => bytes(envelope(id, event)) <= MAX_ENVELOPE;

/** `s` cut to its first `max` UTF-8 bytes at most, at a character
 * boundary. */
function prefixBytes(s, max) {
  let out = '';
  let used = 0;
  for (const c of s) {
    const n = bytes(c);
    if (used + n > max) break;
    out += c;
    used += n;
  }
  return out;
}

/** The longest prefix of `reason`, at a character boundary and ending
 * with `…`, with which `make(reason)`'s envelope fits; `null` if none
 * does. Searched one character at a time: no prefix is skipped. */
function cut(id, reason, make) {
  const chars = [...prefixBytes(reason, MAX_ENVELOPE)];
  let best = null;
  let stem = '';
  for (let n = 0; n <= chars.length; n++) {
    if (n > 0) stem += chars[n - 1];
    const event = make(stem + CUT);
    if (!fits(id, event)) break;
    best = { reason: stem + CUT, event };
  }
  return best;
}

function fitted(id, reason, make) {
  if (bytes(reason) <= MAX_ENVELOPE) {
    const event = make(reason);
    if (fits(id, event)) return event;
  }
  return cut(id, reason, make)?.event ?? null;
}

const summaryText = (count, reasons) => text({ phase: 'peer-failed', summary: { count, reasons } });

/** A summary as it fits: oldest reasons dropped while more than one is
 * left, then the one left cut. Changes `reasons` to what it keeps. */
function fitSummary(id, count, reasons) {
  for (;;) {
    const event = summaryText(count, reasons);
    if (fits(id, event)) return event;
    if (reasons.length <= 1) break;
    reasons.shift();
  }
  const last = reasons.pop();
  const done = cut(id, last, (r) => summaryText(count, [r]));
  reasons.push(done.reason);
  return done.event;
}

/** A clone's queue, as 0008 states it. */
class Queue {
  constructor(id) {
    this.id = id;
    this.seq = 0;
    this.latest = null;
    this.failures = [];
    this.summary = null;
    this.terminal = null;
  }

  push(p) {
    const id = this.id;
    if (['resolving', 'connecting', 'fetching'].includes(p.phase)) {
      const event = progressText(p);
      if (fits(id, event)) this.latest = { seq: ++this.seq, event };
    } else if (p.phase === 'peer-failed') {
      if (this.summary || this.failures.length >= FAILURES) {
        const seq = ++this.seq;
        this.summary ??= { count: 0, reasons: [] };
        this.summary.seq = seq;
        this.summary.count += 1;
        this.summary.reasons.push(prefixBytes(p.reason, MAX_ENVELOPE));
        if (this.summary.reasons.length > REASONS) this.summary.reasons.shift();
        this.summary.event = fitSummary(id, this.summary.count, this.summary.reasons);
      } else {
        const event = fitted(id, p.reason, (reason) => progressText({ ...p, reason }));
        if (event !== null) this.failures.push({ seq: ++this.seq, event });
      }
    } else if (p.phase === 'failed') {
      this.terminal = fitted(id, p.reason, (reason) => progressText({ ...p, reason }));
    } else {
      this.terminal = progressText(p);
    }
  }

  /** Takes the next event written, or null. */
  take() {
    const slots = [
      this.latest && ['latest', this.latest],
      this.failures.length > 0 && ['failure', this.failures[0]],
      this.summary && ['summary', this.summary],
    ].filter(Boolean);
    if (slots.length === 0) {
      const event = this.terminal;
      this.terminal = null;
      return event;
    }
    const [slot, held] = slots.reduce((a, b) => (b[1].seq < a[1].seq ? b : a));
    if (slot === 'latest') this.latest = null;
    else if (slot === 'failure') this.failures.shift();
    else this.summary = null;
    return held.event;
  }
}

/** A reason in a case, written out or as `{ "$repeat": [unit, count] }`. */
const repeat = (unit, count) => ({ $repeat: [unit, count] });
const spelled = (reason) => (typeof reason === 'string' ? reason : reason.$repeat[0].repeat(reason.$repeat[1]));

/** Runs a queue case's steps: `emit` folds an event in, `take` has the
 * writer take that many (or every one left); at the end every one left is
 * taken. What was written, as the envelopes. */
function runQueue(c) {
  const queue = new Queue(c.request_id);
  const written = [];
  const takeOne = () => {
    const event = queue.take();
    if (event !== null) written.push(envelope(c.request_id, event));
    return event !== null;
  };
  for (const step of [...c.steps, { take: 'all' }]) {
    if (step.emit) {
      const p = { ...step.emit };
      if (p.reason !== undefined) p.reason = spelled(p.reason);
      queue.push(p);
    } else if (step.take === 'all') {
      while (takeOne());
    } else {
      for (let n = 0; n < step.take; n++) takeOne();
    }
  }
  return written;
}

const resolving = (candidates) => ({ phase: 'resolving', candidates });
const connecting = (index, total, addr = `seed${index}.example:8776`) => ({ phase: 'connecting', nid: NID, addr, index, total });
const fetching = (index, total) => ({ phase: 'fetching', nid: NID, index, total });
const peerFailed = (index, total, reason) => ({ phase: 'peer-failed', nid: NID, index, total, reason });

/** A candidate that fails: `connecting`, `fetching`, `peer-failed`. */
const candidateFails = (index, total, reason) => [connecting(index, total), fetching(index, total), peerFailed(index, total, reason)].map((emit) => ({ emit }));

function queueCases() {
  const out = [];
  const add = (id, request_id, steps, note) => out.push({ id, request_id, note, steps });
  const emits = (...events) => events.map((emit) => ({ emit }));

  add('phases-keep-the-latest', 1, emits(resolving(3), connecting(1, 3), fetching(1, 3)),
    'resolving, connecting and fetching: only the latest unwritten one is kept');
  add('one-at-a-time', 1, [
    ...emits(resolving(2)), { take: 1 }, ...emits(connecting(1, 2)), { take: 1 }, ...emits(fetching(1, 2)), { take: 1 },
    ...emits(peerFailed(1, 2, 'refused')), { take: 1 }, ...emits(connecting(2, 2, NID2)), { take: 1 }, ...emits(fetching(2, 2)), { take: 1 },
    ...emits({ phase: 'done' }),
  ], 'a writer that keeps up: every event as libradicle wrote it');
  add('failures-keep-their-place', 7, emits(connecting(1, 3), fetching(1, 3), peerFailed(1, 3, 'one'), connecting(2, 3), fetching(2, 3)),
    'a phase event that replaces the latest takes its place as of then');
  const twenty = [];
  for (let n = 1; n <= 20; n++) twenty.push(...candidateFails(n, 21, `reason ${n}`));
  add('eight-failures-then-a-summary', 12, [...emits(resolving(21)), ...twenty, ...emits(connecting(21, 21), fetching(21, 21), { phase: 'done' })],
    'past 8 unwritten failures, one summary counts the rest and keeps the 4 most recent reasons');
  const overflow = [];
  for (let n = 1; n <= 9; n++) overflow.push(...candidateFails(n, 30, `r${n}`));
  add('a-summary-folds-while-it-waits', 3, [
    ...overflow, { take: 1 }, ...candidateFails(10, 30, 'r10'), { take: 9 }, ...candidateFails(11, 30, 'r11'),
    ...candidateFails(12, 30, 'r12'), { take: 1 }, ...candidateFails(13, 30, 'r13'),
  ], 'a failure while the summary waits folds into it, moving it last; once it is written, failures are kept as they are again');
  const contract = [];
  for (let n = 1; n <= 20; n++) contract.push(...candidateFails(n, 21, repeat(MIXED, 600)));
  add('contract-scenario', 41, [...emits(resolving(21)), ...contract, ...emits({ phase: 'done' })],
    'the browser\'s pending contract test: 20 failures whose reasons are 600 of every widening character, nothing written until the end');
  add('cut-a-reason', 2, emits(peerFailed(1, 1, repeat(MIXED, 300))), 'a reason cut to the longest prefix that fits, ending with …');
  add('cut-between-surrogates', 2, emits(peerFailed(1, 1, repeat(ROCKET, 2000))), 'a 4-byte character is never split');
  add('cut-nuls', 2, emits(peerFailed(1, 1, repeat(NUL, 1000))), 'a NUL is 7 bytes in the envelope');
  add('cut-backslashes-and-quotes', 2, emits(peerFailed(1, 1, repeat(`${BS}${QUOTE}`, 1000))), 'a backslash and a quote are 4 each');
  add('cut-with-the-widest-id', 9007199254740991, emits(peerFailed(1, 1, repeat('x', 5000))), 'the ID counts: 16 digits leave 15 bytes less than 1 digit');
  add('cut-with-the-narrowest-id', 1, emits(peerFailed(1, 1, repeat('x', 5000))), 'one digit');
  // An envelope of exactly 4096 bytes is kept whole; one byte more is cut.
  const base = bytes(envelope(5, progressText(peerFailed(1, 1, ''))));
  add('exactly-4096-bytes', 5, emits(peerFailed(1, 1, repeat('y', MAX_ENVELOPE - base))), 'an envelope of exactly 4 KiB is kept whole');
  add('one-byte-over', 5, emits(peerFailed(1, 1, repeat('y', MAX_ENVELOPE - base + 1))), 'one byte more is cut');
  add('a-reason-past-4-kib-is-truncated-first', 5, emits(peerFailed(1, 1, repeat(E_ACUTE, 100000))), 'what no prefix of it can fit changes nothing');
  const long = [];
  for (let n = 1; n <= 8; n++) long.push(peerFailed(n, 20, 'kept'));
  for (let n = 9; n <= 12; n++) long.push(peerFailed(n, 20, `${n}:${'z'.repeat(1500)}`));
  add('a-summary-drops-its-oldest-reasons', 9, emits(...long), 'a summary too large drops its oldest reasons while more than one is left');
  const cutSummary = [];
  for (let n = 1; n <= 8; n++) cutSummary.push(peerFailed(n, 20, 'kept'));
  cutSummary.push(peerFailed(9, 20, 'short'), peerFailed(10, 20, repeat(MIXED, 500)));
  add('a-summary-drops-then-cuts-the-last', 9, emits(...cutSummary), 'then the one reason left is cut');
  add('the-terminal-comes-last', 4, emits(peerFailed(1, 2, 'one'), { phase: 'cancelled' }, fetching(2, 2)),
    'the terminal event has its own slot, after everything queued before it');
  add('a-failed-terminal-is-cut', 4, emits(connecting(1, 1), { phase: 'failed', reason: repeat(MIXED, 1000) }),
    'the terminal event is never dropped: its reason is cut');
  add('a-failed-terminal-fits', 4, emits({ phase: 'failed', reason: `fetching ${RID} failed: ${MIXED}` }), 'libradicle\'s text when it fits');
  return out;
}

// ---- main at the reference ----------------------------------------------

function loadMain(checkout) {
  const world = { script: [], calls: [], warnings: [], infos: [], unscripted: [], progress: [] };
  // What main asks besides the case's own calls: its peer count and its
  // repositories, for the node info it publishes.
  const BACKGROUND = { status: text({ connectedPeers: 2 }), listRepos: '[]' };
  const answer = (name, args) => {
    const shown = args.map((a) => (typeof a === 'function' ? '<callback>' : a));
    world.calls.push({ export: name, args: shown });
    const found = world.script.find((e) => e.export === name && isDeepStrictEqual(e.args, shown) && !e.used);
    if (!found) {
      if (Object.hasOwn(BACKGROUND, name)) return BACKGROUND[name];
      world.unscripted.push({ export: name, args: shown });
      return error(`unscripted ${name}`);
    }
    found.used = true;
    // A clone with progress: each event to the callback, as the add-on's
    // ThreadsafeFunction delivers them, before the call resolves.
    if (found.events) {
      const callback = args.at(-1);
      for (const event of found.events) callback(event);
    }
    return found.text;
  };
  const addon = new Proxy({}, { get: (_, name) => (typeof name === 'string' ? (...args) => answer(name, args) : undefined) });
  const join = (parts) => parts.map((p) => String(p)).join(' ');
  const log = {
    debug() {}, error() {}, log() {},
    info: (...parts) => world.infos.push(join(parts)),
    warn: (...parts) => world.warnings.push(join(parts)),
  };
  const embedded = loadWithInternals(checkout, 'src/main/radicle-embedded.js', [], {
    './logger': log,
    fs: { ...fs, existsSync: (p) => p === ADDON || fs.existsSync(p) },
    [ADDON]: addon,
  });
  const seedStatus = loadWithInternals(checkout, 'src/main/radicle/seed-status.js', [], { '../logger': log });
  const manager = loadWithInternals(checkout, 'src/main/radicle-manager.js', ['connectAndSeedDefault', 'seedRepository', 'getConnections'], {
    electron: { ipcMain: { handle() {}, on() {}, removeHandler() {} }, BrowserWindow: { getAllWindows: () => [] } },
    './logger': log,
    './radicle-embedded': embedded,
    './profile-paths': { getRadicleDataDir: () => '/nonexistent', prepareRadicleDataDir: () => '/nonexistent' },
    './profile-resolver': { getActiveProfile: () => null },
    './radicle/seed-status': seedStatus,
    './service-registry': { MODE: {}, updateService() {}, setStatusMessage() {}, clearService() {} },
  }, 'module.exports.__setRunning = () => { currentState = STATUS.RUNNING; };');
  manager.__setRunning();
  return { world, manager: manager.__internals, seedStatus };
}

/** Lets every queued callback and timer of main's run. */
const settle = async () => {
  for (let n = 0; n < 20; n++) await new Promise((resolve) => setImmediate(resolve));
};

async function runMain(main, script, run) {
  const { world } = main;
  // Each case starts with no fetch on record.
  main.seedStatus._reset();
  world.script = script.map((e) => ({ ...e }));
  world.calls = [];
  world.warnings = [];
  world.infos = [];
  world.unscripted = [];
  const realNow = Date.now;
  let now = 1700000000000;
  Date.now = () => (now += 1);
  try {
    const result = await run();
    await settle();
    assert.deepEqual(world.unscripted, [], 'unscripted add-on calls');
    for (const e of world.script) assert.ok(e.used, `scripted ${e.export} never read`);
    return { ...result, calls: world.calls, infos: world.infos, warnings: world.warnings };
  } finally {
    Date.now = realNow;
  }
}

// ---- the cases ----------------------------------------------------------

function reportCases() {
  const failure = (nid, addr, reason) => ({ nid, addr, reason });
  return [
    { id: 'ready', report: { attempted: 4, connected: 4, target: 4, targetReached: true, elapsedMs: 812, failures: [] } },
    {
      id: 'degraded',
      report: {
        attempted: 14, connected: 1, target: 4, targetReached: false, elapsedMs: 15000,
        failures: [
          failure(NID, 'seed.radicle.garden:8776', 'Connection refused (os error 111)'),
          failure(NID2, '[2001:db8::1]:8776', `peer ${QUOTE}x${QUOTE} said ${BS}${NUL}no`),
          failure(NID, 'caf' + E_ACUTE + '.example:8776', `caf${E_ACUTE} ${ROCKET} timed out`),
        ],
      },
    },
    { id: 'already-connected', report: { attempted: 0, connected: 4, target: 4, targetReached: true, elapsedMs: 0, failures: [] } },
    { id: 'empty-book', report: { attempted: 0, connected: 0, target: 0, targetReached: true, elapsedMs: 0, failures: [] } },
    { id: 'live-peers-reach-the-target', status: 5, report: { attempted: 9, connected: 2, target: 4, targetReached: false, elapsedMs: 15003, failures: [] } },
    { id: 'large-elapsed', report: { attempted: 1, connected: 0, target: 1, targetReached: false, elapsedMs: 4294967325, failures: [failure(NID, 'seed.example:1', 'x')] } },
    { id: 'failed', error: { variant: 'NodeThread', message: 'the node is not running' } },
  ];
}

/** A clone's progress, as libradicle emits it, then its result. */
function progressCases() {
  const all = [
    resolving(3), connecting(1, 3, 'seed.radicle.garden:8776'), fetching(1, 3),
    peerFailed(1, 3, `refused: ${QUOTE}x${QUOTE} ${BS} ${NUL}${ch(0x1f)} caf${E_ACUTE} ${ROCKET} ${ch(0x2028)}`),
    connecting(2, 3, NID2), fetching(2, 3),
  ];
  return [
    { id: 'every-phase-then-done', events: [...all, { phase: 'done' }], result: { ok: true } },
    { id: 'failed', events: [...all, peerFailed(2, 3, 'not connected'), { phase: 'failed', reason: `fetching ${RID} failed: not connected` }], error: { variant: 'FetchFailed', rid: RID, reason: 'not connected' } },
    { id: 'cancelled', events: [resolving(1), connecting(1, 1), { phase: 'cancelled' }], result: { cancelled: true } },
    { id: 'no-seeds', events: [{ phase: 'failed', reason: `no seeds found for ${RID}` }], error: { variant: 'NoSeeds', rid: RID } },
  ];
}

/** libradicle's outcomes of a clone, and the service's answers. */
function resultCases() {
  return [
    { id: 'ok', result: { ok: true } },
    { id: 'cancelled-by-main', libradicle: { variant: 'Cancelled' }, main_cancelled: true },
    { id: 'cancelled-by-the-deadline-or-the-stop', libradicle: { variant: 'Cancelled' }, main_cancelled: false },
    { id: 'no-seeds', libradicle: { variant: 'NoSeeds', rid: RID } },
    { id: 'fetch-failed', libradicle: { variant: 'FetchFailed', rid: RID, reason: `not connected ${QUOTE}${BS}${E_ACUTE}` } },
    { id: 'fetch-failed-not-found', libradicle: { variant: 'FetchFailed', rid: RID, reason: 'repository not found' } },
    { id: 'timeout', libradicle: { variant: 'Timeout', rid: RID } },
    { id: 'node-thread', libradicle: { variant: 'NodeThread', message: 'the node is not running' } },
    { id: 'gated-namespace', libradicle: { variant: 'Gated', rid: RID, state: 'namespace' } },
    { id: 'gated-cache', libradicle: { variant: 'Gated', rid: RID, state: 'cache' } },
    { id: 'gated-repairing', libradicle: { variant: 'Gated', rid: RID, state: 'repairing' } },
  ];
}

/** Today's message test (0008, "Errors"). */
const notFound = (message) => /not found|does not exist|NotFound/i.test(message);

/** The service's answer to a clone libradicle ended so (0008, "Methods"
 * and "Errors"), and whether its outcome is proven. */
function serviceAnswer(c) {
  if (c.result) return { result: c.result, proven: true };
  const e = c.libradicle;
  if (e.variant === 'Cancelled') {
    return c.main_cancelled ? { result: { cancelled: true }, proven: false } : { nothing: true, proven: false };
  }
  if (e.variant === 'Gated') {
    if (e.state === 'repairing') return { error: { code: 'stopped', message: 'the repository is being repaired' }, proven: true };
    // No quarantine record in the home: the gate's kind, and no step.
    return { error: { code: 'quarantined', message: `${e.rid} is quarantined: Radicle couldn't repair it`, data: { kind: e.state, step: null } }, proven: true };
  }
  const message = errorText(e);
  return { error: { code: notFound(message) ? 'not_found' : 'failed', message }, proven: true };
}

async function buildRadicleNetwork(checkout, meta) {
  const previous = process.env.FREEDOM_RADICLE_ADDON;
  process.env.FREEDOM_RADICLE_ADDON = ADDON;
  try {
    const main = loadMain(checkout);
    const reports = [];
    for (const c of reportCases()) {
      const answerText = c.error ? error(errorText(c.error)) : seedReport(c.report);
      const script = [
        { export: 'connectSeeds', args: [15000], text: answerText },
        ...(c.error ? [] : [{ export: 'cloneRepo', args: ['rad:z3QXuMvMmSeEX3ZgoUidZC1v5MkKE', 120000], text: '{"ok":true}' }]),
      ];
      if (c.status !== undefined) script.push({ export: 'status', args: [], text: text({ connectedPeers: c.status }) });
      const ran = await runMain(main, script, async () => {
        await main.manager.connectAndSeedDefault();
        return {};
      });
      const entry = { id: c.id };
      if (c.report) entry.report = c.report;
      if (c.error) entry.libradicle = c.error;
      if (c.status !== undefined) entry.status = c.status;
      entry.text = answerText;
      entry.main = ran;
      // The service's answer: the report's text as it is, or the error.
      entry.expect = c.error
        ? { source: 'design', error: { code: notFound(errorText(c.error)) ? 'not_found' : 'failed', message: errorText(c.error) } }
        : { source: 'design', result_text: answerText };
      reports.push(entry);
    }
    assert.ok(reports.some((r) => r.main.infos.some((l) => l.includes('Seed bootstrap ready'))));
    assert.ok(reports.some((r) => r.main.infos.some((l) => l.includes('Seed bootstrap degraded'))));
    assert.ok(reports.some((r) => r.main.warnings.some((l) => l.includes('Background network initialization failed'))));

    const progress = [];
    for (const c of progressCases()) {
      const events = c.events.map((p) => ({ progress: p, text: progressText(p) }));
      const resultText = c.result ? text(c.result) : error(errorText(c.error));
      const statuses = [];
      const script = [
        { export: 'cloneRepoWithProgress', args: [RID, 120000, '<callback>'], text: resultText, events: events.map((e) => e.text) },
      ];
      if (c.result?.ok) script.push({ export: 'seeders', args: [RID], text: text({ seeding: 2 }) });
      const ran = await runMain(main, script, async () => {
        const started = await main.manager.seedRepository(RID, (status) => statuses.push(JSON.parse(JSON.stringify(status))));
        assert.equal(started.success, true, c.id);
        await started.status.done;
        return { statuses };
      });
      progress.push({ id: c.id, events, result_text: resultText, main: ran });
    }

    const queue = [];
    for (const c of queueCases()) {
      const written = runQueue(c);
      for (const e of written) {
        assert.ok(bytes(e) <= MAX_ENVELOPE, `${c.id}: ${bytes(e)}`);
        const event = JSON.parse(JSON.parse(e).data.event);
        assert.ok(typeof event.phase === 'string', c.id);
      }
      queue.push({ ...c, source: 'design', written });
    }
    // The contract test's expectations hold of the design's queue.
    const contract = queue.find((c) => c.id === 'contract-scenario');
    const events = contract.written.map((e) => JSON.parse(JSON.parse(e).data.event));
    const failures = events.filter((e) => e.phase === 'peer-failed');
    const summaries = failures.filter((e) => e.summary);
    assert.equal(summaries.length, 1);
    assert.ok(failures.length - 1 <= 8);
    assert.equal(failures.length - 1 + summaries[0].summary.count, 20);
    for (const reason of [...failures.filter((e) => !e.summary).map((e) => e.reason), ...summaries[0].summary.reasons]) {
      assert.ok(reason.endsWith(CUT));
      for (const part of [NUL, BS, QUOTE, E_ACUTE, ROCKET]) assert.ok(reason.includes(part));
    }
    assert.equal(events.at(-1).phase, 'done');

    const results = [];
    for (const c of resultCases()) {
      const entry = { id: c.id };
      if (c.result) entry.result_text = text(c.result);
      if (c.libradicle) {
        entry.libradicle = c.libradicle;
        entry.text = c.libradicle.variant === 'Cancelled' ? text({ cancelled: true }) : error(errorText(c.libradicle));
      }
      if (c.main_cancelled !== undefined) entry.main_cancelled = c.main_cancelled;
      const addonText = entry.result_text ?? entry.text;
      const statuses = [];
      const script = [{ export: 'cloneRepoWithProgress', args: [RID, 120000, '<callback>'], text: addonText, events: [] }];
      if (c.result) script.push({ export: 'seeders', args: [RID], text: text({ seeding: 1 }) });
      entry.main = await runMain(main, script, async () => {
        const started = await main.manager.seedRepository(RID, (status) => statuses.push(JSON.parse(JSON.stringify(status))));
        await started.status.done;
        return { final: statuses.at(-1) };
      });
      entry.expect = { source: 'design', ...serviceAnswer(c) };
      results.push(entry);
    }

    return {
      meta,
      formats: {
        reports: '`rad.connect_seeds`: `report` is libradicle\'s `SeedConnectReport` (`elapsedMs` its `elapsed` in milliseconds), `text` the JSON its `json::seed_report` writes, which the add-on\'s `connectSeeds` returns (or the error its failure returns, from `libradicle`: an `Error` variant and its fields); `main` what the reference\'s `connectAndSeedDefault` then did: the add-on calls in order (`status` and `listRepos` answer `connectedPeers` 2 and no repository unless `status` says otherwise), and its info and warning lines. `expect` is the service\'s answer: the report\'s text as its result, byte for byte, or its error.',
        progress: 'A clone\'s progress: each event libradicle emits (`progress`, its phase and fields) with the text its `json::progress` writes, which the add-on hands to `cloneRepoWithProgress`\'s callback, as the `event` of a `rad.progress`; then the clone\'s result text. `main` is what the reference\'s `seedRepository` published (seed-status\'s statuses, `Date.now` counting from 1700000000000) and the calls it made.',
        queue: 'The design\'s progress queue (0008, "Progress"; `source: design`): a clone\'s `request_id` and its `steps`: `emit` folds an event in (a `reason` written as `{ "$repeat": [unit, count] }` is the unit repeated), `take` has the writer take that many; at the end every event left is taken. `written` is every envelope the connection writes, exactly, in order: each at most 4096 bytes.',
        results: 'A clone\'s end: libradicle\'s `Ok` (`result_text`) or its `Error` (`libradicle`, with `text`: the add-on\'s answer), and, for a cancel, whether main cancelled it; `main` is the reference\'s last published status for it; `expect` the service\'s answer (`result`, `error` with its code and message and data, or `nothing`: the deadline or the stop answers it) and whether the outcome is proven (else the dirty marker stays).',
      },
      constants: { max_envelope: MAX_ENVELOPE, failures: FAILURES, reasons: REASONS, cut: CUT },
      reports,
      progress,
      queue,
      results,
    };
  } finally {
    if (previous === undefined) delete process.env.FREEDOM_RADICLE_ADDON;
    else process.env.FREEDOM_RADICLE_ADDON = previous;
  }
}

// radicle-stats.js reads main's peer count through the same harness.
module.exports = { buildRadicleNetwork, loadMain, runMain };
