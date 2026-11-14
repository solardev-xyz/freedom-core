'use strict';

// The key-store helper's answers (design 0013, PRF-1: "The helper,
// `freedom-cored keystore`", "The secret transfer", "The answer", "DPAPI's
// blob"). No reference implementation exists: the helper is new in the
// core, and no build of the browser runs it. So every case and every
// outcome here is the design's, written out by hand below as plain states;
// nothing is computed by a model of the rules. freedom-cored's tests replay
// them: the helper's lines byte for byte, and the core's reading of each
// answer under the fixed request key.
//
// The generator only lays the answers out and seals: each `key` is HPKE
// (RFC 9180, base mode) in the core's suite, composed in hpke.js from
// node:crypto's primitives and pinned there to the RFC's own vectors
// (check.test.js), under fixed recipient and ephemeral keying material,
// with the `info` and associated data each case names. It checks each
// hand-written case's shape, so a typo fails generation instead of passing
// as an expectation.
//
// The formats are in the file's `formats` member.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const hpke = require('./hpke');

const LABEL = 'freedom-keystore/1';
// The Radicle node key's release (design 0008): the same suite, another
// `info` and an empty associated data.
const RADICLE_INFO = 'freedom-radicle-node-key/1';
const AEAD = 'aes-256-gcm';
const MAX_ANSWER_BYTES = 4096;
const SEALED_KEY_BYTES = 80;
const OPS = ['create', 'open', 'forget'];
const BACKENDS = ['macos-keychain', 'dpapi'];
const ERRORS = ['not_found', 'cancelled', 'unavailable', 'invalidated', 'denied', 'backend'];

const FORMATS = {
  suite: 'HPKE (RFC 9180) base mode, single-shot: DHKEM(X25519, HKDF-SHA256) (0x0020), HKDF-SHA256 (0x0001), AES-256-GCM (0x0002). Every key pair is DeriveKeyPair(ikm) (RFC 9180 7.1.3); an ephemeral one comes from 32 bytes of the RNG.',
  info: 'Every answer\'s `info`: the ASCII bytes of `freedom-keystore/1`.',
  aad: 'An answer\'s associated data: the ASCII bytes of `freedom-keystore/1`, a zero byte, the op\'s name, a zero byte, the item\'s 32 lowercase hex digits, and, for an answer that carries a blob, a zero byte and the blob\'s raw SHA-256 (32 bytes).',
  key: 'An answer\'s `key`: standard padded base64 of HPKE\'s enc (32 bytes), then the ciphertext and its 16-byte tag (48 bytes): 80 bytes.',
  line: 'An answer as the helper writes it: one JSON object, no space, members in this order: {"ok":true,"key":<key>} for create and open, with "sealed":<blob, standard padded base64> before "key" for a create that keeps a blob (DPAPI); {"ok":true} for forget; {"ok":false,"error":<error>} or {"ok":false,"error":<error>,"reason":<[a-z0-9_]{1,32}>} for a failure, error one of not_found, cancelled, unavailable, invalidated, denied, backend. Then a newline.',
  recipient: 'The fixed request key: its `ikm`, and the X25519 key pair DeriveKeyPair gives for it (`sk`, `pk`, hex; `pk_base64` as --reply-key spells it). Every answer here is sealed to it but those `sealed` to `other`.',
  helper: 'The helper\'s own answers: `args` after `keystore`, the bytes on stdin (`stdin_hex`), what the OS offers (`offers`: the backend and its policies, or null for no backend), `os`: the one OS call the helper makes, [op, policy, item] with the key it stores for a create (hex), and the store\'s `result` (`ok`, `{ key }` for an open, or `{ failed: [error, reason | null] }`), or null for no call; `rng`: the RNG\'s draws in order, each one fill (hex; the wrapping key for a create, then the seal\'s ephemeral ikm); an RNG past its list fails. `line` is the exact output, newline included, every draw used.',
  answers: 'The core\'s reading of an answer main relays: the request (`op`, the `backend` the core holds the key in, `item`) and the answer\'s exact `text`, as main relays it in the response\'s `result`. `sealed`, when present, says how the generator sealed the `key`: to which recipient, under which info and associated data (hex), with which ephemeral ikm, and the byte it changed after sealing (`damage`: [part, index], part enc or ciphertext; index counts from 0, negative from the end), and `wrap` the wrapping key it sealed (hex). The `outcome`: `{ key }` (hex) with `blob` for a create that keeps one, `{ done: true }` for a forget, or `{ error }`, with `reason` for backend: answer_seal (the key doesn\'t open under the request\'s key, op, item and blob), answer_form (out of form, or not the kind the op needs), answer_too_long (over 4096 bytes), or the helper\'s own (bad_request, duplicate, rng, status, seal, confine; any other is helper).',
};

// ---------------------------------------------------------------------------
// Fixed values: public test values, never used for anything real.

const sha256 = (data) => crypto.createHash('sha256').update(data).digest();
const hex = (b) => Buffer.from(b).toString('hex');
const b64 = (b) => Buffer.from(b).toString('base64');

const RECIPIENT_IKM = sha256('freedom-keystore vector reply key');
const OTHER_IKM = sha256('freedom-keystore vector another reply key');
const RECIPIENT = hpke.deriveKeyPair(RECIPIENT_IKM);
const OTHER = hpke.deriveKeyPair(OTHER_IKM);
const WRAP = Object.fromEntries([1, 2, 3].map((n) => [`w${n}`, sha256(`freedom-keystore vector wrap key ${n}`)]));
const ephemeral = (label) => sha256(`freedom-keystore vector ephemeral ${label}`);
const ITEM = { A: 'a1'.repeat(16), B: 'b2'.repeat(16) };
const blobBytes = (label, length) => {
  const out = Buffer.alloc(length);
  for (let i = 0; i < length; i += 32) sha256(`${label} ${i}`).copy(out, i);
  return out;
};
const BLOB = {
  b1: blobBytes('freedom-keystore vector DPAPI blob 1', 230),
  b2: blobBytes('freedom-keystore vector DPAPI blob 2', 230),
};
// b1 with its first byte changed.
BLOB.b1x = Buffer.from(BLOB.b1);
BLOB.b1x[0] ^= 0x01;

const KEYCHAIN = { backend: 'macos-keychain', unattended: true, user_presence: false };

// ---------------------------------------------------------------------------
// Laying an answer out

const ITEM_RE = /^[0-9a-f]{32}$/;
const REASON_RE = /^[a-z0-9_]{1,32}$/;

// The associated data a seal binds, from the parts the case names.
function aad(op, item, blob) {
  assert.ok(OPS.includes(op), `op ${op}`);
  assert.match(item, ITEM_RE);
  const parts = [Buffer.from(LABEL, 'ascii'), Buffer.from([0]), Buffer.from(op, 'ascii'), Buffer.from([0]), Buffer.from(item, 'ascii')];
  if (blob) parts.push(Buffer.from([0]), sha256(BLOB[blob]));
  return Buffer.concat(parts);
}

// Seals wrapping key `wrap` as a case says: { wrap, op, item, blob?, to?,
// info?, aad? (hex, instead of op/item/blob), ikm, damage? }.
function seal(spec) {
  const associated = spec.aad !== undefined ? Buffer.from(spec.aad, 'hex') : aad(spec.op, spec.item, spec.blob);
  const info = Buffer.from(spec.info ?? LABEL, 'ascii');
  const to = spec.to === 'other' ? OTHER : RECIPIENT;
  const { enc, ct } = hpke.sealBase({ aead: AEAD, pkR: to.pk, ikmE: spec.ikm, info, aad: associated, pt: WRAP[spec.wrap] });
  assert.equal(enc.length, 32);
  assert.equal(ct.length, 48);
  if (spec.damage) {
    const [part, index] = spec.damage;
    const target = { enc, ciphertext: ct }[part];
    assert.ok(target, `damage ${part}`);
    target[index < 0 ? target.length + index : index] ^= spec.damageMask ?? 0x01;
  }
  const sealedKey = Buffer.concat([enc, ct]);
  const sealed = {
    to: spec.to === 'other' ? 'other' : 'recipient',
    info: info.toString('ascii'),
    aad_hex: hex(associated),
    ikm: hex(spec.ikm),
    wrap: hex(WRAP[spec.wrap]),
  };
  if (spec.damage) sealed.damage = spec.damage;
  if (spec.damageMask) sealed.damage_mask = spec.damageMask;
  return { sealedKey, sealed };
}

// The helper's lines (FORMATS.line), laid out by hand.
const keyLine = (sealedKey, blob) => (blob
  ? `{"ok":true,"sealed":"${b64(BLOB[blob])}","key":"${b64(sealedKey)}"}`
  : `{"ok":true,"key":"${b64(sealedKey)}"}`);
const failLine = (error, reason) => {
  assert.ok(ERRORS.includes(error), `error ${error}`);
  if (reason === undefined || reason === null) return `{"ok":false,"error":"${error}"}`;
  assert.match(reason, REASON_RE);
  return `{"ok":false,"error":"${error}","reason":"${reason}"}`;
};
const DONE = '{"ok":true}';

// ---------------------------------------------------------------------------
// The helper's own answers: argv, stdin, the one OS call and the RNG.

const reply = RECIPIENT.pk.toString('base64');
const H = (id, args, { stdin = '', offers = KEYCHAIN, os = null, rng = [], line }) => ({ id, args, stdin, offers, os, rng, line });
const sealedLine = (id, wrap, op, item) => keyLine(seal({ wrap, op, item, ikm: ephemeral(`helper ${id}`) }).sealedKey);
const createArgs = (item) => ['--op', 'create', '--policy', 'unattended', '--item', item, '--reply-key', reply];
const openArgs = (item, ...more) => ['--op', 'open', '--policy', 'unattended', '--item', item, '--reply-key', reply, ...more];
const forgetArgs = (item) => ['--op', 'forget', '--policy', 'unattended', '--item', item];
const draw = (id) => hex(ephemeral(`helper ${id}`));

const HELPER = [
  H('create', createArgs(ITEM.A), {
    os: { call: ['create', 'unattended', ITEM.A, hex(WRAP.w1)], result: 'ok' },
    rng: [hex(WRAP.w1), draw('create')], line: sealedLine('create', 'w1', 'create', ITEM.A),
  }),
  H('open', openArgs(ITEM.A), {
    os: { call: ['open', 'unattended', ITEM.A], result: { key: hex(WRAP.w1) } },
    rng: [draw('open')], line: sealedLine('open', 'w1', 'open', ITEM.A),
  }),
  H('open-with-a-reason', openArgs(ITEM.B, '--reason', 'quick_unlock'), {
    os: { call: ['open', 'unattended', ITEM.B], result: { key: hex(WRAP.w2) } },
    rng: [draw('open-with-a-reason')], line: sealedLine('open-with-a-reason', 'w2', 'open', ITEM.B),
  }),
  H('forget', forgetArgs(ITEM.A), {
    os: { call: ['forget', 'unattended', ITEM.A], result: 'ok' }, line: DONE,
  }),
  H('forget-missing', forgetArgs(ITEM.A), {
    os: { call: ['forget', 'unattended', ITEM.A], result: { failed: ['not_found', null] } }, line: failLine('not_found'),
  }),
  H('open-missing', openArgs(ITEM.A), {
    os: { call: ['open', 'unattended', ITEM.A], result: { failed: ['not_found', null] } }, line: failLine('not_found'),
  }),
  H('open-denied', openArgs(ITEM.A), {
    os: { call: ['open', 'unattended', ITEM.A], result: { failed: ['denied', 'interaction_not_allowed'] } },
    line: failLine('denied', 'interaction_not_allowed'),
  }),
  H('open-item-out-of-form', openArgs(ITEM.A), {
    os: { call: ['open', 'unattended', ITEM.A], result: { failed: ['invalidated', 'item_form'] } },
    line: failLine('invalidated', 'item_form'),
  }),
  H('create-duplicate', createArgs(ITEM.A), {
    os: { call: ['create', 'unattended', ITEM.A, hex(WRAP.w1)], result: { failed: ['backend', 'duplicate'] } },
    rng: [hex(WRAP.w1)], line: failLine('backend', 'duplicate'),
  }),
  // The RNG fails before the wrapping key is made: no OS call.
  H('create-rng-fails', createArgs(ITEM.A), { line: failLine('backend', 'rng') }),
  // It fails at the seal's ephemeral key, after the open.
  H('open-seal-rng-fails', openArgs(ITEM.A), {
    os: { call: ['open', 'unattended', ITEM.A], result: { key: hex(WRAP.w1) } }, line: failLine('backend', 'seal'),
  }),
  H('stdin-byte', openArgs(ITEM.A), { stdin: '00', line: failLine('backend', 'bad_request') }),
  H('create-without-reply-key', ['--op', 'create', '--policy', 'unattended', '--item', ITEM.A], { line: failLine('backend', 'bad_request') }),
  H('forget-with-reply-key', [...forgetArgs(ITEM.A), '--reply-key', reply], { line: failLine('backend', 'bad_request') }),
  H('reason-on-create', [...createArgs(ITEM.A), '--reason', 'quick_unlock'], { line: failLine('backend', 'bad_request') }),
  H('reply-key-low-order', ['--op', 'open', '--policy', 'unattended', '--item', ITEM.A, '--reply-key', b64(Buffer.alloc(32))], { line: failLine('backend', 'bad_request') }),
  H('item-uppercase', openArgs(ITEM.A.toUpperCase()), { line: failLine('backend', 'bad_request') }),
  H('flag-twice', [...openArgs(ITEM.A), '--item', ITEM.B], { line: failLine('backend', 'bad_request') }),
  H('user-presence-not-offered', ['--op', 'open', '--policy', 'user_presence', '--item', ITEM.A, '--reply-key', reply, '--reason', 'quick_unlock'], {
    line: failLine('unavailable', 'unsupported'),
  }),
  H('user-presence-without-reason', ['--op', 'open', '--policy', 'user_presence', '--item', ITEM.A, '--reply-key', reply], {
    line: failLine('backend', 'bad_request'),
  }),
  H('no-backend', openArgs(ITEM.A), { offers: null, line: failLine('unavailable', 'unsupported') }),
  H('no-backend-stdin-byte', openArgs(ITEM.A), { offers: null, stdin: '00', line: failLine('backend', 'bad_request') }),
];

// ---------------------------------------------------------------------------
// The core's reading of each answer, under the fixed request key.

const KC = 'macos-keychain';
const DP = 'dpapi';
const req = (op, backend = KC, item = ITEM.A) => ({ op, backend, item });
// An answer case: `answer` is { text } or { seal, text?: (key) => text }.
const answers = [];
const A = (id, request, answer, outcome) => answers.push({ id, request, answer, outcome });
const S = (id, spec) => ({ ...spec, ikm: ephemeral(`answer ${id}`) });
const ERR = (error, reason) => (reason ? { error, reason } : { error });
const SEAL_REFUSED = ERR('backend', 'answer_seal');
const FORM = ERR('backend', 'answer_form');
const fixedKey = b64(Buffer.alloc(SEALED_KEY_BYTES, 0x5a));

// In form, each op.
A('create', req('create'), { seal: S('create', { wrap: 'w1', op: 'create', item: ITEM.A }) }, { key: hex(WRAP.w1) });
A('open', req('open'), { seal: S('open', { wrap: 'w1', op: 'open', item: ITEM.A }) }, { key: hex(WRAP.w1) });
A('open-item-b', req('open', KC, ITEM.B), { seal: S('open-item-b', { wrap: 'w2', op: 'open', item: ITEM.B }) }, { key: hex(WRAP.w2) });
A('forget', req('forget'), { text: DONE }, { done: true });
A('forget-not-found', req('forget'), { text: failLine('not_found') }, { done: true });
A('dpapi-create', req('create', DP), { seal: S('dpapi-create', { wrap: 'w3', op: 'create', item: ITEM.A, blob: 'b1' }), blob: 'b1' },
  { key: hex(WRAP.w3), blob: b64(BLOB.b1) });
A('dpapi-open', req('open', DP), { seal: S('dpapi-open', { wrap: 'w3', op: 'open', item: ITEM.A }) }, { key: hex(WRAP.w3) });
// 4096 bytes, as relayed: in; one more: out.
A('at-the-cap', req('open'), { seal: S('at-the-cap', { wrap: 'w1', op: 'open', item: ITEM.A }), pad: MAX_ANSWER_BYTES }, { key: hex(WRAP.w1) });
A('over-the-cap', req('open'), { seal: S('over-the-cap', { wrap: 'w1', op: 'open', item: ITEM.A }), pad: MAX_ANSWER_BYTES + 1 },
  ERR('backend', 'answer_too_long'));

// Sealed for another request, or not as the helper seals.
A('create-sealed-for-open', req('create'), { seal: S('create-sealed-for-open', { wrap: 'w1', op: 'open', item: ITEM.A }) }, SEAL_REFUSED);
A('open-sealed-for-create', req('open'), { seal: S('open-sealed-for-create', { wrap: 'w1', op: 'create', item: ITEM.A }) }, SEAL_REFUSED);
A('open-sealed-for-forget', req('open'), { seal: S('open-sealed-for-forget', { wrap: 'w1', op: 'forget', item: ITEM.A }) }, SEAL_REFUSED);
A('open-sealed-for-another-item', req('open'), { seal: S('open-sealed-for-another-item', { wrap: 'w1', op: 'open', item: ITEM.B }) }, SEAL_REFUSED);
A('create-sealed-for-another-item', req('create'), { seal: S('create-sealed-for-another-item', { wrap: 'w1', op: 'create', item: ITEM.B }) }, SEAL_REFUSED);
A('open-sealed-to-another-key', req('open'), { seal: S('open-sealed-to-another-key', { wrap: 'w1', op: 'open', item: ITEM.A, to: 'other' }) }, SEAL_REFUSED);
A('open-sealed-under-another-info', req('open'), { seal: S('open-sealed-under-another-info', { wrap: 'w1', op: 'open', item: ITEM.A, info: RADICLE_INFO }) }, SEAL_REFUSED);
// A Radicle node-key release relayed as an answer: its info, no aad.
A('open-radicle-release', req('open'), { seal: S('open-radicle-release', { wrap: 'w1', info: RADICLE_INFO, aad: '' }) }, SEAL_REFUSED);
A('open-sealed-with-no-aad', req('open'), { seal: S('open-sealed-with-no-aad', { wrap: 'w1', aad: '' }) }, SEAL_REFUSED);
A('open-sealed-with-a-blob-digest', req('open'), { seal: S('open-sealed-with-a-blob-digest', { wrap: 'w1', op: 'open', item: ITEM.A, blob: 'b1' }) }, SEAL_REFUSED);
A('dpapi-create-another-blob', req('create', DP), { seal: S('dpapi-create-another-blob', { wrap: 'w3', op: 'create', item: ITEM.A, blob: 'b1' }), blob: 'b2' }, SEAL_REFUSED);
A('dpapi-create-blob-byte-changed', req('create', DP), { seal: S('dpapi-create-blob-byte-changed', { wrap: 'w3', op: 'create', item: ITEM.A, blob: 'b1' }), blob: 'b1x' }, SEAL_REFUSED);
A('dpapi-create-sealed-without-digest', req('create', DP), { seal: S('dpapi-create-sealed-without-digest', { wrap: 'w3', op: 'create', item: ITEM.A }), blob: 'b1' }, SEAL_REFUSED);
// One changed byte after sealing.
A('enc-first-byte', req('open'), { seal: S('enc-first-byte', { wrap: 'w1', op: 'open', item: ITEM.A, damage: ['enc', 0] }) }, SEAL_REFUSED);
// X25519 ignores the top bit of enc's last byte (RFC 7748): the same
// Diffie-Hellman, but enc is in HPKE's KEM context.
A('enc-masked-bit', req('open'), { seal: S('enc-masked-bit', { wrap: 'w1', op: 'open', item: ITEM.A, damage: ['enc', -1], damageMask: 0x80 }) }, SEAL_REFUSED);
A('ciphertext-first-byte', req('open'), { seal: S('ciphertext-first-byte', { wrap: 'w1', op: 'open', item: ITEM.A, damage: ['ciphertext', 0] }) }, SEAL_REFUSED);
A('ciphertext-last-key-byte', req('open'), { seal: S('ciphertext-last-key-byte', { wrap: 'w1', op: 'open', item: ITEM.A, damage: ['ciphertext', 31] }) }, SEAL_REFUSED);
A('tag-last-byte', req('open'), { seal: S('tag-last-byte', { wrap: 'w1', op: 'open', item: ITEM.A, damage: ['ciphertext', -1] }) }, SEAL_REFUSED);
A('create-tag-first-byte', req('create'), { seal: S('create-tag-first-byte', { wrap: 'w1', op: 'create', item: ITEM.A, damage: ['ciphertext', 32] }) }, SEAL_REFUSED);

// Cut short, too long, or out of form.
const sealOpen = (id) => ({ seal: S(id, { wrap: 'w1', op: 'open', item: ITEM.A }) });
A('key-truncated', req('open'), { ...sealOpen('key-truncated'), keyBytes: [0, SEALED_KEY_BYTES - 1] }, FORM);
A('key-enc-only', req('open'), { ...sealOpen('key-enc-only'), keyBytes: [0, 32] }, FORM);
A('key-a-byte-more', req('open'), { ...sealOpen('key-a-byte-more'), keyExtra: '00' }, FORM);
A('key-unpadded', req('open'), { ...sealOpen('key-unpadded'), text: (key) => `{"ok":true,"key":"${key.replace(/=+$/, '')}"}` }, FORM);
A('line-truncated', req('open'), { ...sealOpen('line-truncated'), text: (key) => `{"ok":true,"key":"${key}"` }, FORM);
A('line-newline-inside', req('open'), { ...sealOpen('line-newline-inside'), text: (key) => `{"ok":true,"key":"${key.slice(0, 54)}\n${key.slice(54)}"}` }, FORM);
A('two-lines', req('open'), { ...sealOpen('two-lines'), text: (key) => `{"ok":true,"key":"${key}"}\n{"ok":true,"key":"${key}"}` }, FORM);
A('trailing-bytes', req('forget'), { text: '{"ok":true} x' }, FORM);
A('empty', req('open'), { text: '' }, FORM);
A('not-json', req('open'), { text: 'ok' }, FORM);
A('an-array', req('open'), { text: '[]' }, FORM);
A('null', req('forget'), { text: 'null' }, FORM);
A('no-ok', req('open'), { ...sealOpen('no-ok'), text: (key) => `{"key":"${key}"}` }, FORM);
A('ok-a-string', req('open'), { ...sealOpen('ok-a-string'), text: (key) => `{"ok":"true","key":"${key}"}` }, FORM);
A('unknown-member', req('open'), { ...sealOpen('unknown-member'), text: (key) => `{"ok":true,"key":"${key}","extra":1}` }, FORM);
A('duplicate-key', req('open'), { ...sealOpen('duplicate-key'), text: (key) => `{"ok":true,"key":"${key}","key":"${key}"}` }, FORM);
A('duplicate-ok', req('open'), { ...sealOpen('duplicate-ok'), text: (key) => `{"ok":true,"ok":true,"key":"${key}"}` }, FORM);
A('duplicate-ok-forget', req('forget'), { text: '{"ok":true,"ok":false,"error":"denied"}' }, FORM);
A('duplicate-error', req('open'), { text: '{"ok":false,"error":"denied","error":"denied"}' }, FORM);
A('null-key', req('open'), { text: '{"ok":true,"key":null}' }, FORM);
A('null-sealed', req('open'), { ...sealOpen('null-sealed'), text: (key) => `{"ok":true,"sealed":null,"key":"${key}"}` }, FORM);
A('null-error', req('open'), { text: '{"ok":false,"error":null}' }, FORM);
A('null-reason', req('open'), { text: '{"ok":false,"error":"denied","reason":null}' }, FORM);
A('key-and-error', req('open'), { ...sealOpen('key-and-error'), text: (key) => `{"ok":true,"key":"${key}","error":"denied"}` }, FORM);
A('failure-with-a-key', req('open'), { text: `{"ok":false,"error":"denied","key":"${fixedKey}"}` }, FORM);
A('failure-without-error', req('open'), { text: '{"ok":false}' }, FORM);
A('failure-unknown-error', req('open'), { text: '{"ok":false,"error":"locked"}' }, FORM);
A('failure-reason-uppercase', req('open'), { text: '{"ok":false,"error":"backend","reason":"Bad"}' }, FORM);
A('failure-reason-empty', req('open'), { text: '{"ok":false,"error":"denied","reason":""}' }, FORM);
A('failure-reason-too-long', req('open'), { text: `{"ok":false,"error":"denied","reason":"${'a'.repeat(33)}"}` }, FORM);
// Not the kind the op needs.
A('open-with-a-blob', req('open'), { seal: S('open-with-a-blob', { wrap: 'w1', op: 'open', item: ITEM.A, blob: 'b1' }), blob: 'b1' }, FORM);
A('dpapi-open-with-a-blob', req('open', DP), { seal: S('dpapi-open-with-a-blob', { wrap: 'w3', op: 'open', item: ITEM.A, blob: 'b1' }), blob: 'b1' }, FORM);
A('keychain-create-with-a-blob', req('create'), { seal: S('keychain-create-with-a-blob', { wrap: 'w1', op: 'create', item: ITEM.A, blob: 'b1' }), blob: 'b1' }, FORM);
A('dpapi-create-without-a-blob', req('create', DP), { seal: S('dpapi-create-without-a-blob', { wrap: 'w3', op: 'create', item: ITEM.A }) }, FORM);
A('blob-without-key', req('create', DP), { text: `{"ok":true,"sealed":"${b64(BLOB.b1)}"}` }, FORM);
A('blob-unpadded', req('create', DP), { ...sealOpen('blob-unpadded'), text: (key) => `{"ok":true,"sealed":"${b64(BLOB.b1).replace(/=+$/, '')}","key":"${key}"}` }, FORM);
A('done-to-create', req('create'), { text: DONE }, FORM);
A('done-to-open', req('open'), { text: DONE }, FORM);
A('key-to-forget', req('forget'), { seal: S('key-to-forget', { wrap: 'w1', op: 'forget', item: ITEM.A }) }, FORM);

// Each failure answer, as the core maps it.
for (const [error, reason, outcome] of [
  ['not_found', null, ERR('not_found')],
  ['cancelled', null, ERR('cancelled')],
  ['unavailable', 'unsupported', ERR('unavailable')],
  ['unavailable', 'timeout', ERR('unavailable')],
  ['unavailable', 'no_keychain', ERR('unavailable')],
  ['invalidated', 'item_form', ERR('invalidated')],
  ['denied', 'auth_failed', ERR('denied')],
  ['denied', 'interaction_not_allowed', ERR('denied')],
  ['backend', 'bad_request', ERR('backend', 'bad_request')],
  ['backend', 'duplicate', ERR('backend', 'duplicate')],
  ['backend', 'rng', ERR('backend', 'rng')],
  ['backend', 'status', ERR('backend', 'status')],
  ['backend', 'seal', ERR('backend', 'seal')],
  ['backend', 'confine', ERR('backend', 'confine')],
  ['backend', 'no_spawn', ERR('backend', 'helper')],
  ['backend', null, ERR('backend', 'helper')],
]) {
  A(`open-${error}${reason ? `-${reason}` : ''}`, req('open'), { text: failLine(error, reason) }, outcome);
}
A('create-backend-duplicate', req('create'), { text: failLine('backend', 'duplicate') }, ERR('backend', 'duplicate'));
A('create-unavailable', req('create'), { text: failLine('unavailable', 'unsupported') }, ERR('unavailable'));
A('dpapi-create-invalidated', req('create', DP), { text: failLine('invalidated') }, ERR('invalidated'));
A('forget-denied', req('forget'), { text: failLine('denied', 'auth_failed') }, ERR('denied'));
A('forget-unavailable', req('forget'), { text: failLine('unavailable', 'timeout') }, ERR('unavailable'));
A('forget-backend', req('forget'), { text: failLine('backend', 'status') }, ERR('backend', 'status'));

// ---------------------------------------------------------------------------

function answerCase({ id, request, answer, outcome }) {
  assert.ok(OPS.includes(request.op) && BACKENDS.includes(request.backend), id);
  assert.match(request.item, ITEM_RE, id);
  const out = { id, request };
  if (answer.seal) {
    const { sealedKey, sealed } = seal(answer.seal);
    let keyBytes = sealedKey;
    if (answer.keyBytes) keyBytes = sealedKey.subarray(...answer.keyBytes);
    if (answer.keyExtra) keyBytes = Buffer.concat([sealedKey, Buffer.from(answer.keyExtra, 'hex')]);
    let text = typeof answer.text === 'function' ? answer.text(b64(keyBytes)) : keyLine(keyBytes, answer.blob);
    if (answer.pad) {
      assert.ok(text.length < answer.pad, id);
      text += ' '.repeat(answer.pad - text.length);
    }
    out.text = text;
    out.sealed = sealed;
  } else {
    assert.equal(typeof answer.text, 'string', id);
    out.text = answer.text;
  }
  assert.equal(Object.keys(outcome).length >= 1, true, id);
  if (outcome.key) assert.match(outcome.key, /^[0-9a-f]{64}$/, id);
  if (outcome.error) {
    assert.ok(ERRORS.includes(outcome.error), id);
    assert.equal(outcome.error === 'backend', 'reason' in outcome, id);
  }
  if (outcome.error === 'backend') assert.ok(FORMATS.answers.includes(outcome.reason), id);
  // Within the cap, but the one case that tests it.
  assert.ok(Buffer.byteLength(out.text) <= MAX_ANSWER_BYTES || outcome.reason === 'answer_too_long', id);
  out.outcome = outcome;
  return out;
}

function helperCase({ id, args, stdin, offers, os, rng, line }) {
  for (const value of args) assert.equal(typeof value, 'string', id);
  assert.match(stdin, /^([0-9a-f]{2})*$/, id);
  for (const value of rng) assert.match(value, /^[0-9a-f]{64}$/, id);
  if (os) {
    assert.ok(OPS.includes(os.call[0]), id);
    assert.equal(os.call.length, os.call[0] === 'create' ? 4 : 3, id);
  }
  assert.ok(line.length <= MAX_ANSWER_BYTES, id);
  return { id, args, stdin_hex: stdin, offers, os, rng, line: `${line}\n` };
}

function buildKeystore(meta) {
  for (const section of [HELPER, answers]) {
    const ids = new Set();
    for (const { id } of section) {
      assert.ok(!ids.has(id), `duplicate id ${id}`);
      ids.add(id);
    }
  }
  return {
    meta,
    source: 'design 0013 (5.4a: The helper, The secret transfer, The answer, DPAPI\'s blob; Vectors: "the helper\'s answers under a fixed request key, with the refusals"): every case and outcome is the design\'s, written by hand in vectors/generator/keystore.js; no reference implementation exists. The generator lays each answer out and seals each key with HPKE composed from node:crypto\'s primitives (vectors/generator/hpke.js, pinned to RFC 9180\'s own test vectors), under fixed keying material, which is public test values.',
    formats: FORMATS,
    constants: {
      label: LABEL,
      kem_id: hpke.KEM_ID,
      kdf_id: hpke.KDF_ID,
      aead_id: hpke.AEADS[AEAD].id,
      max_answer_bytes: MAX_ANSWER_BYTES,
      sealed_key_bytes: SEALED_KEY_BYTES,
    },
    recipient: { ikm: hex(RECIPIENT_IKM), sk: hex(RECIPIENT.sk), pk: hex(RECIPIENT.pk), pk_base64: reply },
    other: { ikm: hex(OTHER_IKM), sk: hex(OTHER.sk), pk: hex(OTHER.pk) },
    blobs: Object.fromEntries(Object.entries(BLOB).map(([name, bytes]) => [name, b64(bytes)])),
    helper: HELPER.map(helperCase),
    answers: answers.map(answerCase),
  };
}

module.exports = { buildKeystore };
