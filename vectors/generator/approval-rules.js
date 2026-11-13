'use strict';

// Design 0012's R-6 limiter and fee check (step APR-2), from the approvals
// reference's own src/main/radicle/auto-write-limiter.js and
// src/main/wallet/fee-check.js. The limiter requires nothing; the fee check
// requires only ../networks/chain-data, for its fetch, which the generator
// stubs and never calls: it asks `readEvidence`, `referenceFee` and
// `judgeFees`, which read nothing.
//
// What the reference decides, and the generator records:
// - `limiter`: runs of `admit` and `forget` under the limiter's own injected
//   `now`, each with its answer. Q9's rate reuses the limiter as it is, one
//   bucket per key and request class (design 0012, "Limits on 'Always
//   allow' (Q9)").
// - `fees`: `readEvidence` of a `chain.fee_reference` reply, `referenceFee`
//   of that evidence at a wall clock and a monotonic one, and `judgeFees` of
//   a transaction against the reference. BigInts are recorded as decimal
//   strings.

const assert = require('node:assert/strict');
const { loadWithInternals } = require('./naming');

// The vault's clock, in milliseconds.
const T0 = 5_000_000;
const DAY = 24 * 60 * 60 * 1000;
const SITE = 'https://app.example';
const OTHER = 'rad://z3gqcJUoA1n9HaHKufZs5FCSGazv5';

function loadLimiter(checkout) {
  return loadWithInternals(checkout, 'src/main/radicle/auto-write-limiter.js', [], {});
}

function loadFeeCheck(checkout) {
  return loadWithInternals(checkout, 'src/main/wallet/fee-check.js', [], {
    '../networks/chain-data': { getFeeReference: () => assert.fail('the fee check fetched') },
  });
}

// ---------------------------------------------------------------------------
// The limiter: each step is [op, key, at].

const admitAt = (key, times) => times.map((at) => ['admit', key, at]);

function dailyRun() {
  // The burst, then one every 30 s: the 50th at T0 + 45 × 30 s. The 51st is
  // refused until exactly 24 hours after the first five.
  const steps = admitAt(SITE, [T0, T0, T0, T0, T0]);
  for (let i = 1; i <= 45; i += 1) steps.push(['admit', SITE, T0 + i * 30_000]);
  steps.push(...admitAt(SITE, [T0 + 2 * 3_600_000, T0 + DAY - 1, T0 + DAY, T0 + DAY, T0 + DAY, T0 + DAY, T0 + DAY, T0 + DAY]));
  return steps;
}

const LIMITER_RUNS = [
  {
    id: 'burst-then-refill',
    steps: [
      ...admitAt(SITE, [T0, T0, T0, T0, T0, T0]),
      ...admitAt(SITE, [T0 + 29_999, T0 + 30_000, T0 + 30_000, T0 + 59_999, T0 + 60_000]),
    ],
  },
  {
    // Refills that add up from parts, as JS adds them in doubles.
    id: 'partial-refills',
    steps: [
      ...admitAt(SITE, [T0, T0, T0, T0, T0]),
      ...admitAt(SITE, [T0 + 10_000, T0 + 20_000, T0 + 30_000]),
      ...admitAt(SITE, [T0 + 37_500, T0 + 45_000, T0 + 52_500, T0 + 60_000]),
      ...admitAt(SITE, [T0 + 60_001, T0 + 61_000, T0 + 62_000, T0 + 89_999, T0 + 90_000, T0 + 90_001]),
      ...admitAt(SITE, Array.from({ length: 30 }, (_, i) => T0 + 90_001 + (i + 1) * 1_000)),
    ],
  },
  { id: 'daily-cap', steps: dailyRun() },
  {
    // Full again after a long wait: no more than the burst.
    id: 'refill-caps-at-burst',
    steps: admitAt(SITE, [T0, T0 + 10 * 60_000, T0 + 10 * 60_000, T0 + 10 * 60_000, T0 + 10 * 60_000, T0 + 10 * 60_000, T0 + 10 * 60_000]),
  },
  {
    id: 'keys-apart-and-forget',
    steps: [
      ...admitAt(SITE, [T0, T0, T0, T0, T0, T0]),
      ...admitAt(OTHER, [T0, T0]),
      ['forget', SITE, T0 + 1],
      ...admitAt(SITE, [T0 + 1, T0 + 1, T0 + 1, T0 + 1, T0 + 1, T0 + 1]),
      ['forget', 'never-seen', T0 + 2],
      ...admitAt(OTHER, [T0 + 2, T0 + 2, T0 + 2, T0 + 2]),
    ],
  },
  {
    // A clock that runs back (the vault's never does): no refill, and the
    // bucket's time moves back with it.
    id: 'clock-back',
    steps: [
      ...admitAt(SITE, [T0, T0, T0, T0, T0]),
      ...admitAt(SITE, [T0 - 60_000, T0 - 30_000, T0 - 1, T0]),
    ],
  },
];

function buildLimiter(checkout) {
  const { createAutoWriteLimiter, LIMITS } = loadLimiter(checkout);
  assert.deepEqual({ ...LIMITS }, { BURST: 5, REFILL_MS: 30_000, DAILY_MAX: 50, DAY_MS: DAY });
  const runs = LIMITER_RUNS.map((run) => {
    let clock = 0;
    const limiter = createAutoWriteLimiter({ now: () => clock });
    const steps = run.steps.map(([op, key, at]) => {
      clock = at;
      if (op === 'forget') return { op, key, at, result: limiter.forget(key) };
      return { op, key, at, result: limiter.admit(key) };
    });
    return { id: run.id, steps };
  });
  return { limits: { burst: LIMITS.BURST, refillMs: LIMITS.REFILL_MS, dailyMax: LIMITS.DAILY_MAX, dayMs: LIMITS.DAY_MS }, runs };
}

// ---------------------------------------------------------------------------
// The fee check.

const GWEI = 1_000_000_000n;
// The wall clock (milliseconds) and the header's own time (seconds).
const WALL = 1_762_000_000_000;
const HEADER_TIME = WALL / 1000;

const header = (fields = {}) => ({ source: 'colibri', number: '21000000', timestamp: String(HEADER_TIME), base_fee: String(10n * GWEI), ...fields });
const quote = (fields = {}) => ({ source: 'direct', type: 'eip1559', maxFeePerGas: String(30n * GWEI), maxPriorityFeePerGas: String(2n * GWEI), answered: 3, ...fields });

// Each: a reply, when it was asked for (the monotonic clock), and when it is
// judged (`wall`, `monotonic`).
const EVIDENCE = [
  { id: 'header', reply: { header: header(), lowest_priority: String(GWEI), quote: quote() } },
  { id: 'header-no-lowest-priority', reply: { header: header(), lowest_priority: null, quote: quote() } },
  { id: 'header-lowest-priority-missing', reply: { header: header(), quote: quote() } },
  { id: 'header-60s-old', reply: { header: header({ timestamp: String(HEADER_TIME - 60) }), lowest_priority: String(GWEI), quote: null } },
  { id: 'header-61s-old', reply: { header: header({ timestamp: String(HEADER_TIME - 61) }), lowest_priority: String(GWEI), quote: quote() } },
  { id: 'header-60s-ahead', reply: { header: header({ timestamp: String(HEADER_TIME + 60) }), lowest_priority: null, quote: null } },
  { id: 'header-61s-ahead', reply: { header: header({ timestamp: String(HEADER_TIME + 61) }), lowest_priority: null, quote: null } },
  { id: 'header-no-base-fee', reply: { header: header({ base_fee: null }), lowest_priority: String(GWEI), quote: quote() } },
  { id: 'header-base-fee-missing', reply: { header: header({ base_fee: undefined }), lowest_priority: String(GWEI), quote: quote() } },
  { id: 'header-zero-base-fee', reply: { header: header({ base_fee: '0' }), lowest_priority: '0', quote: quote() } },
  { id: 'header-not-colibri', reply: { header: header({ source: 'direct' }), lowest_priority: null, quote: quote() } },
  { id: 'header-number-hex', reply: { header: header({ number: '0x10' }), lowest_priority: null, quote: quote() } },
  { id: 'header-leading-zero', reply: { header: header({ base_fee: '010' }), lowest_priority: null, quote: quote() } },
  { id: 'header-78-digits', reply: { header: header({ base_fee: '9'.repeat(78) }), lowest_priority: null, quote: null } },
  { id: 'header-79-digits', reply: { header: header({ base_fee: '1' + '0'.repeat(78) }), lowest_priority: null, quote: quote() } },
  { id: 'lowest-priority-bad', reply: { header: header(), lowest_priority: '1.5', quote: quote() } },
  { id: 'quote', reply: { header: null, lowest_priority: null, quote: quote() } },
  { id: 'quote-one-endpoint', reply: { header: null, lowest_priority: null, quote: quote({ answered: 1 }) } },
  { id: 'quote-legacy', reply: { header: null, lowest_priority: null, quote: { source: 'direct', type: 'legacy', gasPrice: String(20n * GWEI), answered: 2 } } },
  { id: 'quote-legacy-no-gas-price', reply: { header: null, lowest_priority: null, quote: { source: 'direct', type: 'legacy', maxFeePerGas: String(20n * GWEI), answered: 2 } } },
  { id: 'quote-answered-zero', reply: { header: null, lowest_priority: null, quote: quote({ answered: 0 }) } },
  { id: 'quote-answered-text', reply: { header: null, lowest_priority: null, quote: quote({ answered: '3' }) } },
  { id: 'quote-answered-fraction', reply: { header: null, lowest_priority: null, quote: quote({ answered: 1.5 }) } },
  { id: 'quote-not-direct', reply: { header: null, lowest_priority: null, quote: quote({ source: 'quorum' }) } },
  { id: 'quote-unknown-type', reply: { header: null, lowest_priority: null, quote: quote({ type: 'blob' }) } },
  { id: 'quote-zero', reply: { header: null, lowest_priority: null, quote: quote({ maxFeePerGas: '0' }) } },
  { id: 'quote-60s-old', requestedAt: T0 - 60_000, reply: { header: null, lowest_priority: null, quote: quote() } },
  { id: 'quote-61s-old', requestedAt: T0 - 60_001, reply: { header: null, lowest_priority: null, quote: quote() } },
  { id: 'nothing', reply: { header: null, lowest_priority: null, quote: null } },
  { id: 'reply-null', reply: null },
  { id: 'reply-array', reply: [] },
];

const big = (value) => (typeof value === 'bigint' ? value.toString() : value);
const plainEvidence = (evidence) => evidence && JSON.parse(JSON.stringify(evidence, (_, value) => big(value)));

// Each: a transaction's fee fields and the reference it is judged against
// (none, or a fee in wei with its basis).
const R = 10n * GWEI;
const ref = (fee, oneEndpoint = false, basis = 'quote') => ({ fee, basis, oneEndpoint });
const eip1559 = (maxFee, gasLimit = '21000') => ({ maxFeePerGas: String(maxFee), maxPriorityFeePerGas: '1', gasLimit });
const JUDGE = [
  { id: 'at-3r', tx: eip1559(3n * R), reference: ref(R) },
  { id: 'above-3r', tx: eip1559(3n * R + 1n), reference: ref(R) },
  { id: 'below', tx: eip1559(R / 2n), reference: ref(R, false, 'header') },
  { id: 'one-endpoint', tx: eip1559(R), reference: ref(R, true) },
  { id: 'one-endpoint-above', tx: eip1559(4n * R), reference: ref(R, true) },
  { id: 'no-reference', tx: eip1559(R), reference: null },
  { id: 'legacy', tx: { gasPrice: String(2n * R), gasLimit: '100000' }, reference: ref(R) },
  { id: 'max-fee-without-priority', tx: { maxFeePerGas: String(R), gasPrice: String(5n * R), gasLimit: '21000' }, reference: ref(R) },
  { id: 'max-fee-alone', tx: { maxFeePerGas: String(R), gasLimit: '21000' }, reference: ref(R) },
  { id: 'no-fee', tx: { gasLimit: '21000' }, reference: ref(R) },
  { id: 'no-gas-limit', tx: { maxFeePerGas: String(R), maxPriorityFeePerGas: '1' }, reference: ref(R) },
  { id: 'no-fee-no-reference', tx: { gasLimit: '21000' }, reference: null },
  { id: 'ratio-tenths', tx: eip1559(25n * GWEI), reference: ref(R) },
  { id: 'ratio-rounds-half-up', tx: eip1559(1_250_000_000n), reference: ref(GWEI) },
  { id: 'ratio-just-under-ten', tx: eip1559(9_949_999_999n), reference: ref(GWEI) },
  { id: 'ratio-rounds-to-ten', tx: eip1559(9_950_000_000n), reference: ref(GWEI) },
  { id: 'ratio-whole', tx: eip1559(123_456n * GWEI), reference: ref(GWEI) },
  { id: 'ratio-tiny', tx: eip1559(1n), reference: ref(3n) },
  { id: 'ratio-zero-fee', tx: eip1559(0n), reference: ref(R) },
  { id: 'huge', tx: eip1559(2n ** 256n - 1n, String(2n ** 256n - 1n)), reference: ref(2n ** 255n) },
  { id: 'huge-reference', tx: eip1559(2n ** 200n), reference: ref(2n * (10n ** 78n - 1n) + 50_000_000n, false, 'header') },
];

function buildFees(checkout) {
  const fc = loadFeeCheck(checkout);
  assert.equal(fc.FEE_CHECK_MULTIPLE, 3n);
  assert.equal(fc.MIN_PRIORITY_FEE_WEI, 50_000_000n);
  assert.equal(fc.EVIDENCE_MAX_AGE_MS, 60_000);
  const evidence = EVIDENCE.map((c) => {
    const requestedAt = c.requestedAt ?? T0;
    const read = fc.readEvidence(c.reply, requestedAt);
    const reference = fc.referenceFee(read, { wallNow: WALL, monotonicNow: T0 });
    return {
      id: c.id,
      reply: c.reply,
      requestedAt,
      wallNow: WALL,
      monotonicNow: T0,
      evidence: plainEvidence(read),
      reference: plainEvidence(reference),
    };
  });
  // No evidence at all (no reply kept for the chain).
  assert.equal(fc.referenceFee(null, { wallNow: WALL, monotonicNow: T0 }), null);
  const judged = JUDGE.map((c) => ({
    id: c.id,
    tx: c.tx,
    reference: plainEvidence(c.reference),
    verdict: fc.judgeFees(c.tx, c.reference),
  }));
  return { evidence, judged };
}

function buildRules(checkout) {
  return { limiter: buildLimiter(checkout), fees: buildFees(checkout) };
}

const RULES_FORMAT = 'The R-6 limiter (`limiter`): its `limits`, and `runs` of `admit` and `forget` for a `key` under the limiter\'s own clock (`at`, the vault\'s, in milliseconds), each with its `result`; Q9\'s rate reuses it, one bucket per key and request class. The fee check (`fees`): `evidence`, a `chain.fee_reference` `reply` read at `requestedAt` (`readEvidence`, its BigInts as decimal strings) and its `reference` (`referenceFee` at `wallNow` and `monotonicNow`, or null); `judged`, a transaction\'s fee fields (`tx`) judged against a `reference` (or none) by `judgeFees`, with its `verdict`.';

module.exports = { buildRules, RULES_FORMAT };
