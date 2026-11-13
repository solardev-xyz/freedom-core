'use strict';

// Design 0012's standing rules (step APR-2, part 3): whether a site's
// "Always allow" answers a request with no prompt, from the approvals
// reference's own dispatchers, src/main/page/page-signing.js
// (`createSigningDispatchers`: `ruleCovers` and the rule's choice) and
// src/main/page/page-sends.js (`createSendDispatchers`: `ruleMatches`,
// `ruleChosen`, `autoSend`'s fee check and `sendDappPayment`'s pause), each
// driven through the dependencies it takes for its tests:
// - the site's grant: the reference's own dapp-permissions.js over an
//   in-memory file (approval-stores.js's harness), whose `getPermission`,
//   `isTransactionAutoApproved`, `setSigningAutoApprove`,
//   `addTransactionAutoApprove`, `grantPermission`, `revokePermission` and
//   `updateWalletIndex` the dispatchers and the runs call;
// - the fee check: the reference's own fee-check.js `FeeChecks`, with the
//   step's `chain.fee_reference` reply and both clocks injected;
// - #89 and #88: signing-utils.js's `signsRawHash`, `typedDataWarnings`,
//   `toCoreTypedData` and `typedDataViewOptions` (its one package, ethers,
//   stubbed: none of them uses it); wallet-ipc.js's `messageViewFor`,
//   copied, as wallet-ipc.js needs Electron and the vault; and the core's
//   view of typed data as the step names it (`named_type`, `chain`), which
//   the core's replay checks against fc-evm's own view of the same data;
// - custody, the D12 pause, the vault's lock, the quote and the signer, as
//   each step sets them. A prompt the dispatcher opens is closed (the
//   user's rejection), but a vault unlock, which is approved.
//
// What the reference decides, and the generator records (`js`): whether
// the site's rule answered (`rule`: signed or sent with no `eth.sign` or
// `eth.send` prompt), the prompt opened (`prompt`), or the request was
// refused (`error`, the page's error), with every prompt kind it opened.
//
// What the core is expected to answer (`core.expect`): `covered`, or why
// not, as design 0012's API names it, for the core's form of the request,
// against the core's file: `start.core` holds the same grants, each rule in
// Q9's limited form, as Q9's transition writes it, and the runs' ops change
// it as the core does. Where that differs from the reference's choice,
// `deviation` names design 0012's row: `rule-legacy` (today's rules answer
// nothing), `rule-expiry` (30 days of the wall clock from `grantedAt`),
// `rule-rate` (R-6's limiter per key and request class), `rule-value` (a
// rule allowed again takes the new send's value, where today's keeps the
// larger) and `rule-inputs` (custody and the pause come with the request:
// a missing one reads as no rule, as the reference reads one it can't
// tell). The generator checks each step's pair: covered with no deviation
// is the reference's `rule`, a reason with no deviation is its prompt or
// error, and every deviation's reference answer is the one its row says.

const assert = require('node:assert/strict');
const { loadWithInternals } = require('./naming');
const {
  T, SITE, USDC, ROUTER, APPROVE, TRANSFER, USER_DATA, FILES, memoryFs, loadStore, allowSigning, allowTransaction,
} = require('./approval-stores');

const DAY = 24 * 60 * 60 * 1000;
const RULE_TTL_MS = 30 * DAY;
// The wall clock, in milliseconds: rules granted at GRANTED, requests from
// WALL.
const GRANTED = T;
const WALL = T + 60_000;
// The vault's clock, in milliseconds.
const VAULT = 5_000_000;
const GWEI = 1_000_000_000n;
const GNOSIS = 100;
const SAFE = 1000;
const FILE = `${USER_DATA}/${FILES.dapp}`;

// The wallet list, with each account's kind as the core names it.
const ACCOUNTS = [
  { index: 0, name: 'Main Wallet', address: '0x' + '11'.repeat(20), type: 'mnemonic', kind: 'vault' },
  { index: 1, name: 'Ledger', address: '0x' + '22'.repeat(20), type: 'ledger', kind: 'ledger' },
  { index: 2, name: 'Phone', address: '0x' + '33'.repeat(20), type: 'remote', kind: 'phone' },
  { index: SAFE, name: 'Team Safe', address: '0x' + '44'.repeat(20), type: 'safe', kind: 'safe' },
];
const accountOf = (index) => ACCOUNTS.find((account) => account.index === index);

const lower = (text) => text.toLowerCase();
const word = (n) => BigInt(n).toString(16).padStart(64, '0');
// ROUTER's approve and USDC's transfer, the two calls the rules name.
const CALL = Object.freeze({ to: ROUTER, selector: APPROVE, chainId: 1 });
const TOKEN_CALL = Object.freeze({ to: USDC, selector: TRANSFER, chainId: 1 });
const SPENDER = '0x' + '55'.repeat(20);
const approveData = (amount = 1) => `${APPROVE}${word(SPENDER)}${word(amount)}`;
const transferData = (amount) => `${lower(TRANSFER)}${word(SPENDER)}${word(amount)}`;

const HELLO = '0x68656c6c6f';
const TYPED_HASH = `0x${'cd'.repeat(32)}`;
const typed = (fields = {}) => ({
  types: {
    EIP712Domain: [{ name: 'chainId', type: 'uint256' }],
    Order: [{ name: 'amount', type: 'uint256' }],
  },
  domain: { chainId: 1 },
  primaryType: 'Order',
  message: { amount: '1' },
  ...fields,
});
const VIEW_OK = Object.freeze({ named_type: 'match', chain: 'match' });

// The fee check's evidence: a header 21 gwei's reference (twice a 10 gwei
// base fee and 1 gwei of priority), as the core serves it at `at`.
const header = (at, fields = {}) => ({ source: 'colibri', number: '21000000', timestamp: String(Math.floor(at / 1000)), base_fee: String(10n * GWEI), ...fields });
const quote = (fields = {}) => ({ source: 'direct', type: 'eip1559', maxFeePerGas: String(30n * GWEI), maxPriorityFeePerGas: String(2n * GWEI), answered: 3, ...fields });
const evidenceAt = (at) => ({ header: header(at), lowest_priority: String(GWEI), quote: quote() });
const R = 21n * GWEI;
const eip1559 = (maxFee, priority = GWEI) => ({ type: 'eip1559', maxFeePerGas: String(maxFee), maxPriorityFeePerGas: String(priority) });
const GAS = eip1559(30n * GWEI, 2n * GWEI);

const SILENT = { log() {}, info() {}, warn() {}, error() {} };

// ---------------------------------------------------------------------------
// The reference's modules.

function loadReference(checkout) {
  return {
    checkout,
    signing: loadWithInternals(checkout, 'src/main/page/page-signing.js', [], {}),
    // A failure's text goes through rpc-errors' redaction, which needs
    // packages the reference's checkout doesn't install; no text here holds
    // a URL or a key, so it is left as it is. `ethers` gives the prompt's
    // checksummed address only, which no step records.
    sends: loadWithInternals(checkout, 'src/main/page/page-sends.js', [], {
      '../wallet/rpc-errors': { redactRpcText: (text) => text },
      ethers: {},
    }),
    utils: loadWithInternals(checkout, 'src/main/wallet/signing-utils.js', [], { ethers: {} }),
    fees: loadWithInternals(checkout, 'src/main/wallet/fee-check.js', [], {
      '../networks/chain-data': { getFeeReference: () => assert.fail('the fee check fetched') },
    }),
  };
}

/** wallet-ipc.js's `messageViewFor`, over signing-utils.js. */
function messageViewFor(utils, message) {
  if (typeof message !== 'string') {
    throw new Error('The message to sign must be text or 0x-prefixed hex');
  }
  const bytes = utils.messageToBytes(utils.normalizeMessage(message));
  return { hex: '0x' + bytes.toString('hex'), rawHash: utils.signsRawHash(message) };
}

/** `fn` with `Date.now` at `time` and the reference's logging silenced. */
async function at(time, fn) {
  const realNow = Date.now;
  const { log, error, warn, info } = console;
  Date.now = () => time;
  Object.assign(console, SILENT);
  try {
    return await fn();
  } finally {
    Date.now = realNow;
    Object.assign(console, { log, error, warn, info });
  }
}

// ---------------------------------------------------------------------------
// The runs. `start`: the site's grant and rules (none: no file), written by
// the reference for `js` and, each rule in Q9's form, for `core`. Each step
// is a request (`req.*`) with what the core answers, or an op on both files.
// The core replays a run in order, with one limiter for the run: a run of
// the rate holds the vault's clock (`clock: fixed`), and any other moves it
// on by a refill at each request, so that only the rate's runs reach it.

/** The start's two texts: the reference's own writes, then Q9's form. */
async function startFiles(checkout, spec) {
  if (spec === null) return { js: null, core: null };
  const { account = 0, chainId = 1, signing = false, rules = [], thenAccount, legacy = false } = spec;
  const fs = memoryFs();
  const mod = loadStore(checkout, 'dapp', fs);
  await at(GRANTED, () => {
    mod.grantPermission(SITE, account, chainId);
    if (signing) mod.setSigningAutoApprove(SITE, true);
    for (const rule of rules) mod.addTransactionAutoApprove(SITE, rule.to, rule.selector, rule.chainId, rule.value);
    if (thenAccount !== undefined) mod.updateWalletIndex(SITE, thenAccount);
  });
  const js = fs.files.get(FILE);
  if (legacy) return { js, core: js };
  const all = JSON.parse(js);
  if (signing) allowSigning(all[SITE], GRANTED);
  for (const rule of rules) allowTransaction(all[SITE], { to: lower(rule.to), selector: lower(rule.selector), chainId: rule.chainId, value: rule.value }, GRANTED);
  return { js, core: JSON.stringify(all, null, 2) };
}

const req = {
  message: (message, expect, extra = {}) => ({ op: 'request', method: 'personal_sign', params: [message, ACCOUNTS[0].address], expect, ...extra }),
  typed: (typedData, expect, extra = {}) => ({ op: 'request', method: 'eth_signTypedData_v4', params: [ACCOUNTS[0].address, typedData], expect, ...extra }),
  send: (tx, expect, extra = {}) => ({ op: 'request', method: 'eth_sendTransaction', params: [tx], expect, ...extra }),
};
// The page names ROUTER in capitals: a mixed case would have to pass
// EIP-55's checksum when main signs it, which ROUTER's doesn't.
const ROUTER_SENT = `0x${ROUTER.slice(2).toUpperCase()}`;
const approveTx = (value = '0x0', data = approveData()) => ({ to: ROUTER_SENT, value, data });
const op = (name, args = {}, time = WALL) => ({ op: name, args, at: time });
const repeat = (count, make) => Array.from({ length: count }, (_, i) => make(i));

const SIGNING = { signing: true };
const RULED = { rules: [{ ...CALL, value: '1000' }] };

const RUNS = [
  // personal_sign: the grant exposing the account, its signing rule, never
  // 32 bytes (#89), never in custody.
  { id: 'message-rule', start: SIGNING, steps: [req.message(HELLO, 'covered'), req.message('hello', 'covered')] },
  { id: 'message-no-rule', start: {}, steps: [req.message(HELLO, 'no_rule')] },
  { id: 'message-not-connected', start: null, steps: [req.message(HELLO, 'no_rule')] },
  {
    id: 'message-32-bytes',
    start: SIGNING,
    steps: [
      req.message(`0x${'ab'.repeat(32)}`, 'warning'),
      req.message('a'.repeat(32), 'warning'),
      req.message(`0x${'AB'.repeat(32)}`, 'warning'),
      req.message(`0x${'ab'.repeat(31)}`, 'covered'),
      req.message(`0x${'ab'.repeat(33)}`, 'covered'),
      req.message('a'.repeat(31), 'covered'),
      // Two bytes of UTF-8 each: 32 bytes in 16 characters.
      req.message('é'.repeat(16), 'warning'),
    ],
  },
  {
    id: 'message-custody',
    start: SIGNING,
    steps: [
      req.message(HELLO, 'custody', { custody: true }),
      req.message(HELLO, 'custody', { custody: 'unknown', deviation: 'rule-inputs' }),
      req.message(HELLO, 'covered'),
    ],
  },
  {
    // The vault's unlock is the one prompt the rule leaves; the grant moves
    // to another account while it is open, and the rule no longer answers
    // for the account the request signs with.
    id: 'message-account-moved',
    start: SIGNING,
    steps: [
      req.message(HELLO, 'covered', { locked: true }),
      req.message(HELLO, 'no_rule', { locked: true, moveTo: 1 }),
    ],
  },
  { id: 'message-ledger', start: { ...SIGNING, account: 1 }, steps: [req.message(HELLO, 'covered')] },
  { id: 'message-phone', start: { ...SIGNING, account: 2 }, steps: [req.message(HELLO, 'covered')] },
  // A Safe's message, for the Safe's grant (on Gnosis).
  {
    id: 'safe-message',
    start: { ...SIGNING, account: SAFE, chainId: GNOSIS },
    steps: [
      req.message(HELLO, 'covered', { chainId: GNOSIS }),
      req.typed(typed({ domain: { chainId: GNOSIS } }), 'covered', { chainId: GNOSIS }),
      req.message(`0x${'ab'.repeat(32)}`, 'warning', { chainId: GNOSIS }),
      req.message(HELLO, 'custody', { chainId: GNOSIS, custody: true }),
    ],
  },
  { id: 'safe-message-no-rule', start: { account: SAFE, chainId: GNOSIS }, steps: [req.message(HELLO, 'no_rule', { chainId: GNOSIS })] },

  // eth_signTypedData_v4: as a message, and never a view with a warning
  // (#88): a named type other than the root, a domain chain other than the
  // page's, or none.
  {
    id: 'typed-data',
    start: SIGNING,
    steps: [
      req.typed(typed(), 'covered'),
      req.typed(JSON.stringify(typed()), 'covered'),
      req.typed(typed({ domain: { chainId: GNOSIS } }), 'warning', { view: { named_type: 'match', chain: 'mismatch' } }),
      req.typed(
        typed({ types: { EIP712Domain: [{ name: 'name', type: 'string' }], Order: [{ name: 'amount', type: 'uint256' }] }, domain: { name: 'App' } }),
        'warning',
        { view: { named_type: 'match', chain: 'absent' } }
      ),
      req.typed(typed({ primaryType: 'Mail' }), 'warning', { view: { named_type: 'mismatch', chain: 'match' } }),
      req.typed(typed({ primaryType: 7 }), 'warning', { view: { named_type: 'mismatch', chain: 'match' } }),
      req.typed((({ primaryType: _, ...rest }) => rest)(typed()), 'covered', { view: { named_type: 'unknown', chain: 'match' } }),
      req.typed(typed(), 'custody', { custody: true }),
    ],
  },
  { id: 'typed-data-no-rule', start: {}, steps: [req.typed(typed(), 'no_rule')] },

  // eth_sendTransaction: the grant exposing the account, a contract call a
  // rule names for its `to`, selector and chain, with no more value than
  // the rule's; not paused (D12); the fee check; never a Safe's.
  {
    id: 'send-rule',
    start: RULED,
    steps: [
      req.send(approveTx(), 'covered'),
      req.send(approveTx('1000'), 'covered'),
      req.send(approveTx('0x3e8'), 'covered'),
      req.send(approveTx('1001'), 'no_rule'),
      req.send(approveTx('0x0', approveData(1).toUpperCase().replace('0X', '0x')), 'covered'),
      req.send({ ...approveTx(), to: lower(ROUTER) }, 'covered'),
      req.send({ ...approveTx(), to: USDC }, 'no_rule'),
      req.send(approveTx(), 'no_rule', { chainId: 5 }),
      req.send({ ...approveTx(), data: '0x' }, 'no_rule'),
      req.send({ ...approveTx(), data: undefined }, 'no_rule'),
      req.send({ ...approveTx(), data: '0x095ea7' }, 'no_rule'),
      req.send({ ...approveTx(), data: APPROVE }, 'covered'),
      req.send({ ...approveTx(), data: '0x23b872dd' + word(1) }, 'no_rule'),
    ],
  },
  { id: 'send-no-rule', start: {}, steps: [req.send(approveTx(), 'no_rule')] },
  { id: 'send-not-connected', start: null, steps: [req.send(approveTx(), 'no_rule')] },
  {
    id: 'send-custody',
    start: RULED,
    steps: [
      req.send(approveTx(), 'custody', { custody: true }),
      req.send(approveTx(), 'custody', { custody: 'unknown', deviation: 'rule-inputs' }),
    ],
  },
  {
    // D12: paused when the rule is chosen, or in the send's own turn; a
    // pause that can't be read is a pause.
    id: 'send-paused',
    start: RULED,
    steps: [
      req.send(approveTx(), 'paused', { pause: { chosen: true } }),
      req.send(approveTx(), 'paused', { pause: { chosen: 'throws' }, deviation: 'rule-inputs' }),
      req.send(approveTx(), 'paused', { pause: { turnBusy: true } }),
      req.send(approveTx(), 'paused', { pause: { waiting: true } }),
      req.send(approveTx(), 'covered'),
    ],
  },
  {
    // 0005's check A: at most 3·R, a reference from more than one
    // endpoint, and one at all. A phone account picks its own fee.
    id: 'send-fees',
    start: RULED,
    steps: [
      req.send(approveTx(), 'covered', { gasPrices: eip1559(3n * R) }),
      req.send(approveTx(), 'fee_check', { gasPrices: eip1559(3n * R + 1n) }),
      req.send(approveTx(), 'covered', { gasPrices: { type: 'legacy', gasPrice: String(3n * R) } }),
      req.send(approveTx(), 'fee_check', { gasPrices: { type: 'legacy', gasPrice: String(3n * R + 1n) } }),
      req.send(approveTx(), 'fee_check', { evidence: null }),
      req.send(approveTx(), 'fee_check', { evidence: { header: null, lowest_priority: null, quote: quote() }, evidenceAnswered: 1 }),
      // A stale header: the quote's reference (30 gwei, three endpoints).
      req.send(approveTx(), 'covered', { evidenceHeaderAge: 61, gasPrices: eip1559(90n * GWEI) }),
      req.send(approveTx(), 'fee_check', { evidenceHeaderAge: 61, gasPrices: eip1559(90n * GWEI + 1n) }),
      req.send(approveTx(), 'fee_check', { evidence: { header: null, lowest_priority: null, quote: null } }),
    ],
  },
  { id: 'send-ledger', start: { ...RULED, account: 1 }, steps: [req.send(approveTx(), 'covered'), req.send(approveTx(), 'fee_check', { gasPrices: eip1559(3n * R + 1n) })] },
  {
    id: 'send-phone',
    start: { ...RULED, account: 2 },
    steps: [
      req.send(approveTx(), 'covered', { gasPrices: eip1559(1000n * GWEI) }),
      req.send(approveTx(), 'covered', { evidence: null }),
      req.send(approveTx(), 'paused', { pause: { chosen: true } }),
    ],
  },
  {
    // A rule from another account's send, and the grant now on a Safe: no
    // rule answers a Safe's send.
    id: 'send-safe',
    start: { rules: [{ ...CALL, chainId: GNOSIS, value: '0' }], chainId: GNOSIS, thenAccount: SAFE },
    steps: [req.send(approveTx(), 'no_rule', { chainId: GNOSIS })],
  },
  {
    // Q9's value: a rule caps native value per call; a token's amount is
    // in `data`, and its selector covers any.
    id: 'send-value',
    start: { rules: [{ ...CALL, value: '1000' }, { ...TOKEN_CALL, value: '0' }] },
    steps: [
      req.send({ to: USDC, value: '0x0', data: transferData(2n ** 256n - 1n) }, 'covered'),
      req.send({ to: USDC, value: '0x1', data: transferData(1) }, 'no_rule'),
      req.send(approveTx('1000'), 'covered'),
      op('allow-transaction', { call: CALL, value: '500' }, WALL + 1),
      req.send(approveTx('500'), 'covered', { at: WALL + 2 }),
      req.send(approveTx('501'), 'no_rule', { at: WALL + 2, deviation: 'rule-value' }),
      req.send(approveTx('1000'), 'no_rule', { at: WALL + 2, deviation: 'rule-value' }),
      req.send(approveTx('1001'), 'no_rule', { at: WALL + 2 }),
      op('allow-transaction', { call: CALL, value: '2000' }, WALL + 3),
      req.send(approveTx('2000'), 'covered', { at: WALL + 4 }),
    ],
  },

  // Q9: today's rules answer nothing.
  {
    id: 'legacy-rules',
    start: { signing: true, rules: [{ ...CALL, value: '1000' }], legacy: true },
    steps: [
      req.message(HELLO, 'no_rule', { deviation: 'rule-legacy' }),
      req.typed(typed(), 'no_rule', { deviation: 'rule-legacy' }),
      req.send(approveTx(), 'no_rule', { deviation: 'rule-legacy' }),
      op('allow-signing', {}, WALL + 1),
      req.message(HELLO, 'covered', { at: WALL + 2 }),
      req.send(approveTx(), 'no_rule', { at: WALL + 2, deviation: 'rule-legacy' }),
      op('allow-transaction', { call: CALL, value: '0' }, WALL + 3),
      req.send(approveTx(), 'covered', { at: WALL + 4 }),
      req.send(approveTx('1'), 'no_rule', { at: WALL + 4, deviation: 'rule-value' }),
    ],
  },

  // Q9's expiry: 30 days of the wall clock from `grantedAt`; expired at
  // exactly 30 days, and under a clock set before it; the same after a
  // restart, from the file; a new "Always allow" replaces it.
  {
    id: 'signing-expiry',
    start: SIGNING,
    steps: [
      req.message(HELLO, 'covered', { at: GRANTED }),
      req.message(HELLO, 'covered', { at: GRANTED + RULE_TTL_MS - 1 }),
      req.message(HELLO, 'no_rule', { at: GRANTED + RULE_TTL_MS, deviation: 'rule-expiry' }),
      req.message(HELLO, 'no_rule', { at: GRANTED - 1, deviation: 'rule-expiry' }),
      op('restart', {}, GRANTED + RULE_TTL_MS - 1),
      req.typed(typed(), 'covered', { at: GRANTED + RULE_TTL_MS - 1 }),
      req.typed(typed(), 'no_rule', { at: GRANTED + RULE_TTL_MS, deviation: 'rule-expiry' }),
      op('allow-signing', {}, GRANTED + RULE_TTL_MS),
      req.message(HELLO, 'covered', { at: GRANTED + RULE_TTL_MS }),
      req.message(HELLO, 'covered', { at: GRANTED + 2 * RULE_TTL_MS - 1 }),
      req.message(HELLO, 'no_rule', { at: GRANTED + 2 * RULE_TTL_MS, deviation: 'rule-expiry' }),
      req.message(HELLO, 'no_rule', { at: GRANTED + RULE_TTL_MS - 1, deviation: 'rule-expiry' }),
    ],
  },
  {
    id: 'transaction-expiry',
    start: RULED,
    steps: [
      req.send(approveTx(), 'covered', { at: GRANTED + RULE_TTL_MS - 1 }),
      req.send(approveTx(), 'no_rule', { at: GRANTED + RULE_TTL_MS, deviation: 'rule-expiry' }),
      req.send(approveTx(), 'no_rule', { at: GRANTED - 1, deviation: 'rule-expiry' }),
      op('restart', {}, GRANTED + RULE_TTL_MS),
      req.send(approveTx(), 'no_rule', { at: GRANTED + RULE_TTL_MS, deviation: 'rule-expiry' }),
      op('allow-transaction', { call: CALL, value: '1000' }, GRANTED + RULE_TTL_MS),
      req.send(approveTx(), 'covered', { at: GRANTED + RULE_TTL_MS }),
    ],
  },

  // Q9's rate: R-6's limiter, one bucket per key for its signatures and
  // one for its transactions, which all its rules share; over it, the
  // prompt. A request approved there isn't counted.
  {
    id: 'signature-rate',
    clock: 'fixed',
    start: SIGNING,
    steps: [
      ...repeat(5, () => req.message(HELLO, 'covered')),
      req.typed(typed(), 'rate_limited', { deviation: 'rule-rate' }),
      req.message(HELLO, 'rate_limited', { vaultAt: VAULT + 29_999, deviation: 'rule-rate' }),
      req.message(HELLO, 'covered', { vaultAt: VAULT + 30_000 }),
      req.message(HELLO, 'rate_limited', { vaultAt: VAULT + 30_000, deviation: 'rule-rate' }),
      // The transactions' bucket is apart.
      req.send(approveTx(), 'no_rule', { vaultAt: VAULT + 30_000 }),
      req.typed(typed(), 'covered', { vaultAt: VAULT + 60_000 }),
    ],
  },
  {
    id: 'transaction-rate',
    clock: 'fixed',
    start: { signing: true, rules: [{ ...CALL, value: '1000' }, { ...TOKEN_CALL, value: '0' }] },
    steps: [
      ...repeat(5, (i) => (i % 2 === 0
        ? req.send(approveTx(), 'covered')
        : req.send({ to: USDC, value: '0x0', data: transferData(5) }, 'covered'))),
      req.send({ to: USDC, value: '0x0', data: transferData(5) }, 'rate_limited', { deviation: 'rule-rate' }),
      req.send(approveTx(), 'rate_limited', { deviation: 'rule-rate' }),
      // A refusal for another reason counts nothing.
      req.send(approveTx(), 'fee_check', { gasPrices: eip1559(3n * R + 1n) }),
      // Signatures have their own bucket.
      req.message(HELLO, 'covered'),
      req.send(approveTx(), 'covered', { vaultAt: VAULT + 30_000 }),
      req.send(approveTx(), 'rate_limited', { vaultAt: VAULT + 30_000, deviation: 'rule-rate' }),
      // A restart starts every bucket full.
      op('restart', {}, WALL),
      ...repeat(5, () => req.send(approveTx(), 'covered', { vaultAt: VAULT + 30_000 })),
      req.send(approveTx(), 'rate_limited', { vaultAt: VAULT + 30_000, deviation: 'rule-rate' }),
    ],
  },
  {
    // A revoke forgets both buckets; the new grant needs its prompts again.
    id: 'revoke-forgets-buckets',
    clock: 'fixed',
    start: { signing: true, rules: [{ ...CALL, value: '1000' }] },
    steps: [
      ...repeat(5, () => req.message(HELLO, 'covered')),
      ...repeat(5, () => req.send(approveTx(), 'covered')),
      req.message(HELLO, 'rate_limited', { deviation: 'rule-rate' }),
      req.send(approveTx(), 'rate_limited', { deviation: 'rule-rate' }),
      op('revoke', {}, WALL + 1),
      req.message(HELLO, 'no_rule', { at: WALL + 1 }),
      op('connect', { account: 0, chainId: 1 }, WALL + 2),
      req.message(HELLO, 'no_rule', { at: WALL + 2 }),
      op('allow-signing', {}, WALL + 3),
      op('allow-transaction', { call: CALL, value: '0' }, WALL + 3),
      ...repeat(5, () => req.message(HELLO, 'covered', { at: WALL + 4 })),
      ...repeat(5, () => req.send(approveTx(), 'covered', { at: WALL + 4 })),
      req.message(HELLO, 'rate_limited', { at: WALL + 4, deviation: 'rule-rate' }),
    ],
  },
];

// ---------------------------------------------------------------------------
// Running them.

/** The pause the core is sent: a missing one where the reference can't read it. */
function pausedInput(pause) {
  if (pause.chosen === 'throws') return null;
  return pause.chosen === true || pause.turnBusy === true || pause.waiting === true;
}

function evidenceOf(step) {
  if (step.evidence === null) return null;
  if (step.evidence !== undefined) {
    const evidence = JSON.parse(JSON.stringify(step.evidence));
    if (step.evidenceAnswered !== undefined) evidence.quote.answered = step.evidenceAnswered;
    return evidence;
  }
  const evidence = evidenceAt(step.at);
  if (step.evidenceHeaderAge !== undefined) evidence.header = header(step.at - step.evidenceHeaderAge * 1000);
  return evidence;
}

/** The transaction main signs for a page's send (page-sends.js's `quote` and `sendTxOf`). */
function sentTxOf(sends, params, chainId, gasPrices, gasLimit) {
  const tx = sends.txOf(params);
  const fees = gasPrices.type === 'eip1559'
    ? { maxFeePerGas: gasPrices.maxFeePerGas, maxPriorityFeePerGas: gasPrices.maxPriorityFeePerGas }
    : { gasPrice: gasPrices.gasPrice };
  return { to: tx.to, value: tx.value, data: tx.data, chainId, gasLimit, ...fees };
}

const DEVIATIONS = new Set(['rule-legacy', 'rule-expiry', 'rule-rate', 'rule-value', 'rule-inputs']);
const REASONS = new Set(['no_rule', 'paused', 'fee_check', 'custody', 'rate_limited', 'warning']);

async function runOne(env, run) {
  const { checkout, signing, sends, utils, fees } = env;
  const start = await startFiles(checkout, run.start);
  const fs = memoryFs();
  if (start.js !== null) fs.files.set(FILE, start.js);
  // The core's file, changed as the core changes it: the reference's own
  // connect and revoke, which the core writes alike (`stores`), and Q9's
  // "Always allow", as `rollback` writes it.
  let coreText = start.core;
  let perms = loadStore(checkout, 'dapp', fs);

  let step = null;
  let prompts = [];
  let effects = [];
  let judged = [];
  let checks = null;

  const shared = {
    getPermission: (key) => perms.getPermission(key),
    updateLastUsed: (key) => perms.updateLastUsed(key),
    walletList: async () => ACCOUNTS.map(({ kind: _, ...account }) => ({ ...account })),
    chainIdOf: () => step.chainId,
    chainName: () => null,
    networks: () => ({}),
    // No agent answers a tab in custody here: the request goes on, with
    // no rule.
    agentAnswer: async () => null,
  };
  const inCustody = () => {
    if (step.custody === 'unknown') throw new Error('custody unknown');
    return step.custody;
  };
  const isVaultUnlocked = async () => step.locked !== true;
  const signingDispatchers = signing.createSigningDispatchers(shared, {
    inCustody,
    isVaultUnlocked,
    messageView: (message) => messageViewFor(utils, message),
    typedDataView: async () => ({ hash: TYPED_HASH, view: { ...step.view }, warnings: utils.typedDataWarnings(step.view) }),
    signsRawHash: utils.signsRawHash,
    getSigner: () => ({
      signMessage: async () => {
        effects.push('signed');
        return '0xsignature';
      },
      signTypedData: async () => {
        effects.push('signed');
        return '0xsignature';
      },
    }),
    setSigningAutoApprove: (key, enabled) => perms.setSigningAutoApprove(key, enabled),
    startSafeMessage: async () => ({ complete: true, token: 'safe-message' }),
    completeSafeMessage: () => {
      effects.push('signed');
      return { signature: '0xsafesignature' };
    },
    cancelSafeMessage: () => {},
  });
  const sendDispatchers = sends.createSendDispatchers(shared, {
    inCustody,
    isVaultUnlocked,
    ruleMatches: (key, to, selector, chainId, value) => perms.isTransactionAutoApproved(key, to, selector, chainId, value),
    rulePaused: async () => {
      if (step.pause.chosen === 'throws') throw new Error('pause unknown');
      return step.pause.chosen === true;
    },
    addTransactionAutoApprove: (key, to, selector, chainId, value) => perms.addTransactionAutoApprove(key, to, selector, chainId, value),
    takeSiteTurn: async (_site, { wait }) => {
      if (!wait && step.pause.turnBusy === true) throw Object.assign(new Error('busy'), { code: 'SITE_TURN_BUSY' });
      return () => {};
    },
    sitePaymentWaiting: async () => step.pause.waiting === true,
    getSigner: () => ({}),
    signAndRecord: async (tx, _signer, _context, options) => {
      if (options.guardCommit) await options.guardCommit(() => null);
      effects.push('sent');
      options.onCommitted?.();
      return { hash: `0x${'ee'.repeat(32)}` };
    },
    estimateGas: async () => ({ gasLimit: step.gasLimit }),
    getGasPrices: async () => ({ ...step.gasPrices }),
    checkFees: (tx) => {
      judged.push(tx);
      return checks.check(tx);
    },
    checkAtApproval: (tx, options) => checks.atApproval(tx, options),
    startSafeSend: async () => assert.fail('a Safe send started'),
    onSafeSendSettled: () => () => {},
    guardSiteSafeSend: () => () => {},
    siteWithdrawn: () => new Error('withdrawn'),
  });
  const dispatchers = { ...signingDispatchers, ...sendDispatchers };

  const steps = [];
  let requests = 0;
  for (const [index, s] of run.steps.entries()) {
    const label = `${run.id} step ${index}`;
    if (s.op !== 'request') {
      const { to, selector, chainId } = s.args.call ?? {};
      await at(s.at, () => {
        if (s.op === 'allow-signing') perms.setSigningAutoApprove(SITE, true);
        else if (s.op === 'allow-transaction') perms.addTransactionAutoApprove(SITE, to, selector, chainId, s.args.value);
        else if (s.op === 'revoke') perms.revokePermission(SITE);
        else if (s.op === 'connect') perms.grantPermission(SITE, s.args.account, s.args.chainId);
        else if (s.op === 'restart') perms = loadStore(checkout, 'dapp', fs);
        else assert.fail(`${label}: ${s.op}`);
      });
      if (s.op === 'allow-signing' || s.op === 'allow-transaction') {
        const all = JSON.parse(coreText);
        if (s.op === 'allow-signing') allowSigning(all[SITE], s.at);
        else allowTransaction(all[SITE], { to: lower(to), selector: lower(selector), chainId, value: s.args.value }, s.at);
        coreText = JSON.stringify(all, null, 2);
      } else if (s.op === 'revoke' || s.op === 'connect') {
        const coreFs = memoryFs();
        if (coreText !== null) coreFs.files.set(FILE, coreText);
        const mod = loadStore(checkout, 'dapp', coreFs);
        await at(s.at, () => (s.op === 'revoke' ? mod.revokePermission(SITE) : mod.grantPermission(SITE, s.args.account, s.args.chainId)));
        coreText = coreFs.files.get(FILE) ?? null;
      }
      const args = s.args.call
        ? { to: lower(to), selector: lower(selector), chainId, value: s.args.value }
        : { ...s.args };
      steps.push({ op: s.op, args, at: s.at, coreText: s.op === 'restart' ? undefined : coreText });
      continue;
    }

    step = {
      custody: false,
      locked: false,
      chainId: 1,
      at: WALL,
      // The vault's clock: a run of the rate holds it (`clock: fixed`);
      // any other moves it on by a refill at each request, so that its
      // bucket never empties.
      vaultAt: run.clock === 'fixed' ? VAULT : VAULT + requests * 30_000,
      view: VIEW_OK,
      pause: {},
      gasPrices: GAS,
      gasLimit: '60000',
      ...s,
    };
    step.pause = { chosen: false, turnBusy: false, waiting: false, ...step.pause };
    requests += 1;
    const evidence = evidenceOf(step);
    checks = new fees.FeeChecks({
      fetch: async () => {
        if (evidence === null) throw new Error('no reference for the chain');
        return JSON.parse(JSON.stringify(evidence));
      },
      wallClock: () => step.at,
      monotonic: () => step.vaultAt,
      log: SILENT,
    });
    prompts = [];
    effects = [];
    judged = [];
    const before = perms.getPermission(SITE);
    const account = before ? before.walletIndex : 0;
    const context = {
      requester: { key: SITE, guest: 7 },
      method: s.method,
      params: s.params,
      signal: new AbortController().signal,
      approvalsDocument: false,
      nameHolds: async () => true,
      holdsKey: () => true,
      leaveWalletSlot: () => {},
      confirm: () => 'token',
      spend: () => ({ hash: TYPED_HASH }),
      prompt: async (prompt) => {
        prompts.push(prompt.kind);
        if (prompt.kind === 'vault.unlock') {
          if (s.moveTo !== undefined) perms.updateWalletIndex(SITE, s.moveTo);
          return { approve: true, choices: {} };
        }
        return { closed: true };
      },
    };
    const out = await at(step.at, () => dispatchers[`ethereum:${s.method}`](context));
    let js;
    if (prompts.includes('eth.sign') || prompts.includes('eth.send')) {
      assert.deepEqual(effects, [], `${label}: prompted and signed`);
      js = { outcome: 'prompt', prompts };
    } else if (out.error) {
      js = { outcome: 'error', error: out.error, prompts };
    } else {
      assert.ok(effects.length > 0, `${label}: answered without a signature`);
      js = { outcome: 'rule', prompts };
    }

    // The core's form of the request.
    const kind = accountOf(account).kind;
    let request;
    if (s.method === 'personal_sign') {
      request = { kind: 'message', bytes: messageViewFor(utils, s.params[0]).hex };
    } else if (s.method === 'eth_signTypedData_v4') {
      const data = utils.normalizeTypedData(s.params[1]);
      const options = utils.typedDataViewOptions(data, step.chainId);
      request = {
        kind: 'typed-data',
        typedData: utils.toCoreTypedData(data),
        ...(Object.hasOwn(options, 'primaryType') ? { primaryType: options.primaryType } : {}),
        chainId: options.chainId,
        view: { ...step.view },
      };
    } else {
      const tx = sentTxOf(sends, s.params, step.chainId, step.gasPrices, step.gasLimit);
      // The transaction the reference judged, where it judged one, is the one the core is sent.
      for (const one of judged) assert.deepEqual(one, tx, `${label}: judged another transaction`);
      request = {
        kind: 'transaction',
        tx,
        paused: pausedInput(step.pause),
        evidence: evidence === null ? null : { reply: evidence, requestedAt: step.vaultAt },
      };
    }
    if (s.moveTo !== undefined) {
      // The grant moved while the unlock was open: in the core's file too,
      // before it decides.
      const coreFs = memoryFs();
      coreFs.files.set(FILE, coreText);
      const mod = loadStore(checkout, 'dapp', coreFs);
      await at(step.at, () => mod.updateWalletIndex(SITE, s.moveTo));
      coreText = coreFs.files.get(FILE);
    }

    // The pair, as design 0012 relates them.
    assert.ok(s.expect === 'covered' || REASONS.has(s.expect), `${label}: ${s.expect}`);
    const covered = s.expect === 'covered';
    if (!s.deviation) {
      if (covered) assert.equal(js.outcome, 'rule', `${label}: the reference didn't answer by its rule`);
      else assert.notEqual(js.outcome, 'rule', `${label}: the reference's rule answered`);
    } else {
      assert.ok(DEVIATIONS.has(s.deviation), label);
      assert.ok(!covered, `${label}: a deviation the core covers`);
      if (s.deviation === 'rule-inputs') assert.notEqual(js.outcome, 'rule', label);
      else assert.equal(js.outcome, 'rule', `${label}: ${s.deviation}, but the reference's rule didn't answer`);
    }

    steps.push({
      op: 'request',
      method: s.method,
      params: s.params,
      at: step.at,
      vaultAt: step.vaultAt,
      chainId: step.chainId,
      custody: step.custody,
      ...(s.method === 'eth_sendTransaction' ? { pause: step.pause, gasPrices: step.gasPrices } : {}),
      ...(s.moveTo !== undefined ? { moveTo: s.moveTo } : {}),
      js,
      core: {
        agent: step.custody === 'unknown' ? null : step.custody,
        account,
        accountKind: kind,
        ...(s.moveTo !== undefined ? { moveTo: s.moveTo } : {}),
        request,
        expect: s.expect,
        ...(s.deviation ? { deviation: s.deviation } : {}),
      },
    });
  }
  return { id: run.id, key: SITE, start, steps };
}

async function buildDecisions(checkout) {
  const env = loadReference(checkout);
  const runs = [];
  for (const run of RUNS) runs.push(await runOne(env, run));
  // Every reason and every Q9 deviation has a step.
  const steps = runs.flatMap((run) => run.steps.filter((s) => s.op === 'request'));
  for (const reason of ['covered', ...REASONS]) assert.ok(steps.some((s) => s.core.expect === reason), reason);
  for (const deviation of DEVIATIONS) assert.ok(steps.some((s) => s.core.deviation === deviation), deviation);
  return {
    accounts: ACCOUNTS.map(({ index, type, kind }) => ({ index, type, kind })),
    ruleTtlMs: RULE_TTL_MS,
    runs,
  };
}

const DECISIONS_FORMAT = 'Design 0012\'s standing rules, from the reference\'s page-signing.js and page-sends.js driven with injected dependencies: `accounts`, the wallet list (`type` as the reference names it, `kind` as the core does); `runs`, each for the site `key`, from `start` (the dApp file\'s text as the reference wrote it, `js`, and the same grants with each rule in Q9\'s limited form, `core`; null: no file). Each step is an op on both files (`allow-signing`, `allow-transaction` with its `args`, `revoke`, `connect`, at `at`, the wall clock, with the core\'s text after it, `coreText`; `restart`: a new process, every bucket full) or a `request`: the page\'s `method` and `params`, at `at` (the wall clock) and `vaultAt` (the vault\'s clock), on chain `chainId`, with `custody` (`unknown`: unreadable), the D12 `pause` and the quote (`gasPrices`) for a send, and `moveTo`, an account the grant moves to while the vault\'s unlock is open. `js`: what the reference did (`rule`, answered with no `eth.sign` or `eth.send` prompt; `prompt`; `error`, with the page\'s error) and the prompts it opened. `core`: the request as the core takes it (`agent`, `account` and its `accountKind`, `moveTo` applied to the core\'s file before it decides, and `request`: a message\'s `bytes`; typed data in the core\'s form with `primaryType` and `chainId` as the view is asked for, and the `view` fields the core\'s view must hold; or the `tx` main signs, `paused`, null when unreadable, and the fee check\'s `evidence`, a `chain.fee_reference` `reply` asked for at `requestedAt` on the vault\'s clock, or null for none), and `expect`, `covered` or the reason design 0012\'s API names, with `deviation` where Q9 or the request\'s inputs change the reference\'s answer.';

module.exports = { buildDecisions, DECISIONS_FORMAT };
