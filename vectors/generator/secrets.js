'use strict';

// Secrets-file vectors (design 0013, PRF-1a: "The secrets file", "The
// failure contract", "Forgetting an item", "The bounds"). No reference
// implementation exists: the file is new in the core, and no build of the
// browser reads or writes it. So every case and every outcome here is the
// design's, written out by hand below as plain states; nothing is computed
// by a model of the rules. fc-keystore's tests replay them.
//
// The generator only lays the files out: it writes each state as
// `JSON.stringify(file, null, 2)` and seals each entry with Node's
// AES-256-GCM under the state's fixed key and nonce, with the associated
// data the design gives. It checks every hand-written state's shape (ids,
// names, bindings, their order), so a typo fails generation instead of
// passing as an expectation.
//
// The formats are in the file's `formats` member.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const VERSION = 1;
const AAD_LABEL = 'freedom-secrets/1';
const POLICIES = ['unattended', 'user_presence'];
const BACKENDS = ['macos-keychain', 'secret-service', 'dpapi'];
const MAX_ITEMS = 4;
const MAX_ENTRIES = 32;
const MAX_NAME_BYTES = 64;
const MAX_SECRET_BYTES = 1024;
const MAX_BINDING_MEMBERS = 4;
const MAX_BINDING_NAME_BYTES = 32;
const MAX_BINDING_VALUE_BYTES = 128;
const MAX_BLOB_BYTES = 1024;
const MAX_FILE_BYTES = 128 * 1024;

const FORMATS = {
  text: 'A secrets file\'s bytes: `text` (UTF-8), `text_hex` (any bytes) or `text_repeat` ([unit, count]: the unit repeated). A file the core writes is JSON.stringify(file, null, 2), with no newline after it.',
  file: '{ version: 1, keys: { <policy>: { backend, item: <32 hex> | null, sealed: <base64> | null, pending: { backend, item } | null } }, forget: [ { backend, policy, item } ], entries: { <name>: { key: <policy>, nonce: <base64, 12 bytes>, ciphertext: <base64: AES-256-GCM ciphertext, then the 16-byte tag>, binding: { <member>: <text> } } } }. keys by policy (unattended, then user_presence), forget in the order its records were added, entries by name, binding members by name.',
  aad: 'An entry\'s associated data: the ASCII bytes of `freedom-secrets/1`, a zero byte, the entry\'s name, a zero byte, and the binding\'s canonical JSON (JSON.stringify of its members in order of name: no space; values are printable ASCII, so only `"` and `\\` are escaped).',
  files: 'Files in form. `items` is every item the file names, in its order: each key\'s committed item then its pending one, by policy, then the forget list (what a profile delete records, and what fc-profile\'s reader finds). `entries` gives each entry\'s wrapping key, nonce, binding, canonical JSON, associated data (hex) and secret, as the generator sealed it; an entry `sealed_as` another name, binding, key or nonce, or with its last byte `flipped`, was sealed so on purpose. `opens` opens an entry by `name` with the caller\'s `binding` under `key` (hex): `secret` (text), or `error`: no_entry (no such entry), other_binding (the file binds it to something else: nothing is decrypted) or refused (it doesn\'t open: another name, binding or key, or a changed byte).',
  malformed: 'Texts refused, each with the first `reason` the core finds: too_large (over 128 KiB), json (not UTF-8 JSON), version (no `version` 1), form (a member missing, extra, of another type or out of form), items (more than four items named), entries (more than 32 entries), duplicate (an item id twice, or one nonce twice under one key), key_not_in_use (an entry under a key the file doesn\'t hold committed), key_unused (a committed key with no entry), not_canonical (in form, but not the text the core writes for it).',
  transitions: 'One change to the file `before`. `op`: ["begin_create", policy, backend, item] records item as pending before `create` runs; ["commit", sealed, new_key, old_key | null, put | null] makes the pending item sealed names its policy\'s key (sealed: { backend, policy, item, blob: base64 | null }), re-wrapping the policy\'s entries in order of name from old_key to new_key, then writes put under it; ["put", policy, key, put] writes put under the policy\'s committed key; ["remove", name]; ["settle"], at a profile\'s open; ["forgotten", item], after its forget answered ok or not_found; ["drop_foreign", backend | null], the backend this OS has. put is { name, binding, secret (text) }; keys are hex. `rng` lists the RNG\'s draws in order, each one fill of a 12-byte nonce (hex); an RNG past its list fails. The result is `after` (exactly that text, every draw used) or `refused`: forget_backlog, named, not_pending, no_key, other_key, no_entry, entries, secret_size, key_needed, entry_refused or randomness, with nothing changed.',
};

// ---------------------------------------------------------------------------
// Fixed values: public test values, never used for anything real.

const sha256 = (text) => crypto.createHash('sha256').update(text).digest();
const hex = (b) => Buffer.from(b).toString('hex');
const b64 = (b) => Buffer.from(b).toString('base64');

const WRAP = Object.fromEntries([1, 2, 3, 4, 5, 6].map((n) => [`k${n}`, sha256(`fc-keystore vector wrap key ${n}`)]));
const NONCE = Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`n${i + 1}`, sha256(`fc-keystore vector nonce ${i + 1}`).subarray(0, 12)]));
const nonceFor = (label) => {
  if (NONCE[label]) return NONCE[label];
  return sha256(`fc-keystore vector nonce ${label}`).subarray(0, 12);
};
const ITEM = {
  A: 'a1'.repeat(16),
  B: 'b2'.repeat(16),
  C: 'c3'.repeat(16),
  D: 'd4'.repeat(16),
  E: 'e5'.repeat(16),
  F: 'f6'.repeat(16),
  G: '07'.repeat(16),
  H: '18'.repeat(16),
};
const blob = (label, length) => {
  const out = Buffer.alloc(length);
  for (let i = 0; i < length; i += 32) sha256(`${label} ${i}`).copy(out, i);
  return b64(out);
};
const BLOB1 = blob('fc-keystore vector DPAPI blob 1', 230);
const BLOB2 = blob('fc-keystore vector DPAPI blob 2', 250);
const VAULT1 = hex(sha256('fc-keystore vector vault 1'));
const VAULT2 = hex(sha256('fc-keystore vector vault 2'));
const KEYSTORE1 = hex(sha256('fc-keystore vector swarm.key 1'));
const QB = { vault_sha256: VAULT1 };

// ---------------------------------------------------------------------------
// Laying a state out

const ITEM_RE = /^[0-9a-f]{32}$/;
const NAME_RE = /^[a-z][a-z0-9._-]*$/;
const MEMBER_RE = /^[a-z][a-z0-9_]*$/;

function checkBinding(binding) {
  const names = Object.keys(binding);
  assert.ok(names.length <= MAX_BINDING_MEMBERS, 'binding members');
  assert.deepEqual(names, [...names].sort(), 'binding members in order');
  for (const name of names) {
    assert.ok(MEMBER_RE.test(name) && name.length <= MAX_BINDING_NAME_BYTES, `binding member ${name}`);
    const value = binding[name];
    assert.ok(typeof value === 'string' && /^[\x20-\x7e]+$/.test(value) && value.length <= MAX_BINDING_VALUE_BYTES, `binding value ${name}`);
  }
}

const canonical = (binding) => {
  checkBinding(binding);
  return JSON.stringify(binding);
};

const aad = (name, binding) => Buffer.concat([
  Buffer.from(AAD_LABEL, 'ascii'), Buffer.from([0]), Buffer.from(name, 'ascii'), Buffer.from([0]),
  Buffer.from(canonical(binding), 'ascii'),
]);

function gcm(key, nonce, associated, secret) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(associated);
  const body = Buffer.concat([cipher.update(secret), cipher.final()]);
  return Buffer.concat([body, cipher.getAuthTag()]);
}

// What the generator sealed for an entry, and how.
function sealEntry(name, entry) {
  const as = { name, binding: entry.binding, wrap: entry.wrap, nonce: entry.nonce, ...(entry.sealedAs || {}) };
  const sealed = gcm(WRAP[as.wrap], nonceFor(as.nonce), aad(as.name, as.binding), Buffer.from(entry.secret, 'utf8'));
  if (entry.flip) sealed[sealed.length - 1] ^= 1;
  return { as, sealed };
}

// A hand-written state: { keys: { policy: { backend, item, sealed, pending } },
// forget: [ { backend, policy, item } ], entries: { name: { key, wrap, nonce,
// secret, binding, sealedAs?, flip? } } }, laid out as the file's object.
function fileObject(state) {
  const keys = {};
  for (const policy of Object.keys(state.keys)) assert.ok(POLICIES.includes(policy), `policy ${policy}`);
  for (const policy of POLICIES) {
    const key = state.keys[policy];
    if (!key) continue;
    assert.ok(BACKENDS.includes(key.backend), 'backend');
    assert.ok(key.item === null || ITEM_RE.test(key.item), 'item');
    if (key.pending) assert.ok(BACKENDS.includes(key.pending.backend) && ITEM_RE.test(key.pending.item), 'pending');
    keys[policy] = {
      backend: key.backend,
      item: key.item,
      sealed: key.sealed ?? null,
      pending: key.pending ? { backend: key.pending.backend, item: key.pending.item } : null,
    };
  }
  const forget = state.forget.map((f) => {
    assert.ok(BACKENDS.includes(f.backend) && POLICIES.includes(f.policy) && ITEM_RE.test(f.item), 'forget record');
    return { backend: f.backend, policy: f.policy, item: f.item };
  });
  const names = Object.keys(state.entries);
  assert.deepEqual(names, [...names].sort(), 'entries in order of name');
  const entries = {};
  for (const name of names) {
    const entry = state.entries[name];
    assert.ok(NAME_RE.test(name) && name.length <= MAX_NAME_BYTES, `name ${name}`);
    assert.ok(POLICIES.includes(entry.key) && WRAP[entry.wrap], `entry ${name}`);
    const { sealed } = sealEntry(name, entry);
    entries[name] = { key: entry.key, nonce: b64(nonceFor(entry.nonce)), ciphertext: b64(sealed), binding: { ...entry.binding } };
  }
  return { version: VERSION, keys, forget, entries };
}

const textOf = (object) => JSON.stringify(object, null, 2);
const fileText = (state) => textOf(fileObject(state));

function itemsOf(state) {
  const out = [];
  for (const policy of POLICIES) {
    const key = state.keys[policy];
    if (!key) continue;
    if (key.item) out.push({ backend: key.backend, policy, item: key.item });
    if (key.pending) out.push({ backend: key.pending.backend, policy, item: key.pending.item });
  }
  for (const f of state.forget) out.push({ backend: f.backend, policy: f.policy, item: f.item });
  return out;
}

function entriesOf(state) {
  return Object.entries(state.entries).map(([name, entry]) => {
    const { as } = sealEntry(name, entry);
    const out = {
      name, key: entry.key, wrap_key: hex(WRAP[entry.wrap]), nonce: hex(nonceFor(entry.nonce)),
      binding: entry.binding, canonical: canonical(entry.binding), aad: hex(aad(name, entry.binding)), secret: entry.secret,
    };
    const sealedAs = {};
    if (as.name !== name) sealedAs.name = as.name;
    if (as.binding !== entry.binding) sealedAs.binding = as.binding;
    if (as.wrap !== entry.wrap) sealedAs.wrap_key = hex(WRAP[as.wrap]);
    if (as.nonce !== entry.nonce) sealedAs.nonce = hex(nonceFor(as.nonce));
    if (Object.keys(sealedAs).length) out.sealed_as = sealedAs;
    if (entry.flip) out.flipped = true;
    return out;
  });
}

// ---------------------------------------------------------------------------
// States

const mk = 'macos-keychain';
const ss = 'secret-service';
const dp = 'dpapi';
const key = (backend, item, pending = null, sealed = null) => ({ backend, item, sealed, pending });
const pend = (backend, item) => ({ backend, item });
const fr = (backend, policy, item) => ({ backend, policy, item });
const entry = (keyPolicy, wrap, nonce, secret, binding, extra = {}) => ({ key: keyPolicy, wrap, nonce, secret, binding, ...extra });

const S = {};
S.empty = { keys: {}, forget: [], entries: {} };
S.pendingA = { keys: { unattended: key(mk, null, pend(mk, ITEM.A)) }, forget: [], entries: {} };
S.enrolled = {
  keys: { unattended: key(mk, ITEM.A) },
  forget: [],
  entries: { 'quick-unlock': entry('unattended', 'k1', 'n1', 'correct horse battery staple', QB) },
};
S.twoEntries = {
  keys: { unattended: key(mk, ITEM.A) },
  forget: [],
  entries: {
    'quick-unlock': entry('unattended', 'k1', 'n1', 'correct horse battery staple', QB),
    'rpc-api-key.alchemy': entry('unattended', 'k1', 'n2', 'alchemy-api-key-0123', {}),
  },
};
S.replacing = { ...S.twoEntries, keys: { unattended: key(mk, ITEM.A, pend(mk, ITEM.B)) } };
S.replaced = {
  keys: { unattended: key(mk, ITEM.B) },
  forget: [fr(mk, 'unattended', ITEM.A)],
  entries: {
    'quick-unlock': entry('unattended', 'k2', 'n3', 'correct horse battery staple', QB),
    'rpc-api-key.alchemy': entry('unattended', 'k2', 'n4', 'alchemy-api-key-0123', {}),
  },
};
S.pendingC = { ...S.replaced, keys: { unattended: key(mk, ITEM.B), user_presence: key(mk, null, pend(mk, ITEM.C)) } };
// A pending item and a forget list at the bound: four items named.
S.full = {
  ...S.replaced,
  keys: { unattended: key(mk, ITEM.B), user_presence: key(mk, null, pend(mk, ITEM.D)) },
  forget: [fr(mk, 'unattended', ITEM.A), fr(mk, 'user_presence', ITEM.C)],
};
S.afterForgetA = { ...S.full, forget: [fr(mk, 'user_presence', ITEM.C)] };
S.fullAgain = { ...S.afterForgetA, keys: { unattended: key(mk, ITEM.B, pend(mk, ITEM.E)), user_presence: key(mk, null, pend(mk, ITEM.D)) } };
S.settled = {
  ...S.replaced,
  keys: { unattended: key(mk, ITEM.B) },
  forget: [fr(mk, 'user_presence', ITEM.C), fr(mk, 'unattended', ITEM.E), fr(mk, 'user_presence', ITEM.D)],
};
S.oneLeft = {
  ...S.settled,
  entries: { 'quick-unlock': entry('unattended', 'k2', 'n3', 'correct horse battery staple', QB) },
};
S.allForgotten = {
  keys: {},
  forget: [fr(mk, 'user_presence', ITEM.C), fr(mk, 'unattended', ITEM.E), fr(mk, 'user_presence', ITEM.D), fr(mk, 'unattended', ITEM.B)],
  entries: {},
};
S.copied = {
  keys: { unattended: key(ss, ITEM.H) },
  forget: [fr(ss, 'unattended', ITEM.F), fr(mk, 'user_presence', ITEM.G)],
  entries: { 'bee-password': entry('unattended', 'k1', 'n5', 'bee-keystore-password', { keystore_sha256: KEYSTORE1 }) },
};
S.copiedNative = { ...S.copied, forget: [fr(ss, 'unattended', ITEM.F)] };
S.copiedNone = { ...S.copied, forget: [] };
S.dpapiPending = { keys: { unattended: key(dp, null, pend(dp, ITEM.F)) }, forget: [], entries: {} };
S.dpapi = {
  keys: { unattended: key(dp, ITEM.F, null, BLOB1) },
  forget: [],
  entries: { 'bee-password': entry('unattended', 'k3', 'n6', 'bee-keystore-password', { keystore_sha256: KEYSTORE1 }) },
};
S.dpapiReplacing = { ...S.dpapi, keys: { unattended: key(dp, ITEM.F, pend(dp, ITEM.G), BLOB1) } };
S.dpapiReplaced = {
  keys: { unattended: key(dp, ITEM.G, null, BLOB2) },
  forget: [],
  entries: { 'bee-password': entry('unattended', 'k4', 'n7', 'bee-keystore-password', { keystore_sha256: KEYSTORE1 }) },
};
S.dpapiPendingAgain = { ...S.dpapiReplaced, keys: { unattended: key(dp, ITEM.G, pend(dp, ITEM.H), BLOB2) } };
// A pending-only key takes its new pending item's backend.
S.switchedPending = { keys: { unattended: key(ss, null, pend(ss, ITEM.H)) }, forget: [], entries: {} };
// A copied profile's DPAPI key replaced by a Keychain one.
S.dpapiToKeychain = { ...S.dpapi, keys: { unattended: key(dp, ITEM.F, pend(mk, ITEM.H), BLOB1) } };
S.keychainFromDpapi = {
  keys: { unattended: key(mk, ITEM.H) },
  forget: [],
  entries: { 'bee-password': entry('unattended', 'k5', 'n8', 'bee-keystore-password', { keystore_sha256: KEYSTORE1 }) },
};
S.twoKeys = {
  keys: { unattended: key(mk, ITEM.A), user_presence: key(mk, ITEM.B) },
  forget: [],
  entries: {
    // One nonce under each of two keys: allowed.
    export: entry('user_presence', 'k2', 'n1', 'export-secret', {}),
    'quick-unlock': entry('unattended', 'k1', 'n1', 'correct horse battery staple', QB),
  },
};
S.maxEntries = {
  keys: { unattended: key(mk, ITEM.A) },
  forget: [],
  entries: Object.fromEntries(Array.from({ length: MAX_ENTRIES }, (_, i) => [
    `e${String(i).padStart(2, '0')}`, entry('unattended', 'k1', `e${i}`, `secret ${i}`, {}),
  ])),
};

S.maxEntriesReplaced = {
  ...S.maxEntries,
  entries: { ...S.maxEntries.entries, e31: entry('unattended', 'k1', 'r31', 'secret 31 again', {}) },
};

// ---------------------------------------------------------------------------
// Files in form, with their opens

const open = (name, binding, wrap, outcome) => ({ name, binding, key: hex(WRAP[wrap]), ...outcome });

const FILES = [
  { id: 'empty', state: S.empty, opens: [open('quick-unlock', QB, 'k1', { error: 'no_entry' })] },
  {
    id: 'enrolled', state: S.enrolled,
    opens: [
      open('quick-unlock', QB, 'k1', { secret: 'correct horse battery staple' }),
      open('quick-unlock', QB, 'k2', { error: 'refused' }),
      open('quick-unlock', { vault_sha256: VAULT2 }, 'k1', { error: 'other_binding' }),
      open('quick-unlock', {}, 'k1', { error: 'other_binding' }),
      open('export', QB, 'k1', { error: 'no_entry' }),
    ],
  },
  {
    id: 'two-keys', state: S.twoKeys,
    opens: [
      open('export', {}, 'k2', { secret: 'export-secret' }),
      open('export', {}, 'k1', { error: 'refused' }),
      open('quick-unlock', QB, 'k1', { secret: 'correct horse battery staple' }),
      open('quick-unlock', QB, 'k2', { error: 'refused' }),
    ],
  },
  {
    id: 'moved-from-another-name',
    state: { ...S.enrolled, entries: { 'quick-unlock': entry('unattended', 'k1', 'n1', 'correct horse battery staple', QB, { sealedAs: { name: 'export' } }) } },
    opens: [open('quick-unlock', QB, 'k1', { error: 'refused' })],
  },
  {
    id: 'bound-to-another-binding',
    state: { ...S.enrolled, entries: { 'quick-unlock': entry('unattended', 'k1', 'n1', 'correct horse battery staple', { vault_sha256: VAULT2 }, { sealedAs: { binding: QB } }) } },
    opens: [
      open('quick-unlock', { vault_sha256: VAULT2 }, 'k1', { error: 'refused' }),
      open('quick-unlock', QB, 'k1', { error: 'other_binding' }),
    ],
  },
  {
    id: 'under-another-key',
    state: { ...S.enrolled, entries: { 'quick-unlock': entry('unattended', 'k1', 'n1', 'correct horse battery staple', QB, { sealedAs: { wrap: 'k2' } }) } },
    opens: [
      open('quick-unlock', QB, 'k1', { error: 'refused' }),
      open('quick-unlock', QB, 'k2', { secret: 'correct horse battery staple' }),
    ],
  },
  {
    id: 'another-nonce',
    state: { ...S.enrolled, entries: { 'quick-unlock': entry('unattended', 'k1', 'n1', 'correct horse battery staple', QB, { sealedAs: { nonce: 'n2' } }) } },
    opens: [open('quick-unlock', QB, 'k1', { error: 'refused' })],
  },
  {
    id: 'tag-changed',
    state: { ...S.enrolled, entries: { 'quick-unlock': entry('unattended', 'k1', 'n1', 'correct horse battery staple', QB, { flip: true }) } },
    opens: [open('quick-unlock', QB, 'k1', { error: 'refused' })],
  },
  {
    id: 'escaped-binding',
    state: { ...S.enrolled, entries: { 'quick-unlock': entry('unattended', 'k1', 'n1', 'p', { a_quote: 'say "hi"', b_backslash: 'C:\\x', z: '~' }) } },
    opens: [open('quick-unlock', { a_quote: 'say "hi"', b_backslash: 'C:\\x', z: '~' }, 'k1', { secret: 'p' })],
  },
  {
    id: 'longest-secret',
    state: { ...S.enrolled, entries: { 'quick-unlock': entry('unattended', 'k1', 'n1', 'x'.repeat(MAX_SECRET_BYTES), QB) } },
    opens: [open('quick-unlock', QB, 'k1', { secret: 'x'.repeat(MAX_SECRET_BYTES) })],
  },
  { id: 'pending-and-forget-at-the-bound', state: S.full, opens: [open('quick-unlock', QB, 'k2', { secret: 'correct horse battery staple' })] },
  { id: 'dpapi', state: S.dpapi, opens: [open('bee-password', { keystore_sha256: KEYSTORE1 }, 'k3', { secret: 'bee-keystore-password' })] },
  { id: 'dpapi-pending', state: S.dpapiPendingAgain, opens: [] },
  { id: 'copied-from-another-os', state: S.copied, opens: [open('bee-password', { keystore_sha256: KEYSTORE1 }, 'k1', { secret: 'bee-keystore-password' })] },
  { id: 'max-entries', state: S.maxEntries, opens: [open('e31', {}, 'k1', { secret: 'secret 31' })] },
];

// ---------------------------------------------------------------------------
// Malformed texts: a file in form, changed in one way.

const base = () => fileObject(S.replaced);
const withObject = (state, change) => {
  const object = fileObject(state);
  change(object);
  return textOf(object);
};
const replacedWith = (change) => withObject(S.replaced, change);
const sevenWith = (change) => withObject(S.full, change);
const dpapiWith = (change) => withObject(S.dpapi, change);
const replaceText = (text, from, to) => {
  assert.ok(text.includes(from), `no ${from}`);
  return text.replace(from, to);
};
const ENTRY = (o) => o.entries['quick-unlock'];
const KEY = (o) => o.keys.unattended;
const sevenNonce = (byte) => b64(Buffer.alloc(byte, 7));
const ciphertextOf = (length) => b64(Buffer.alloc(length, 9));

const MALFORMED = [
  { id: 'too-large', text_repeat: [' ', MAX_FILE_BYTES + 1], reason: 'too_large' },
  { id: 'empty-text', text: '', reason: 'json' },
  { id: 'cut-short', text: textOf(base()).slice(0, -1), reason: 'json' },
  { id: 'byte-order-mark', text: `\ufeff${textOf(base())}`, reason: 'json' },
  { id: 'not-utf8', text_hex: hex(Buffer.concat([Buffer.from('{"version":1,"x":"'), Buffer.from([0xff]), Buffer.from('"}')])), reason: 'json' },
  { id: 'array', text: '[]', reason: 'form' },
  { id: 'version-2', text: replacedWith((o) => { o.version = 2; }), reason: 'version' },
  { id: 'version-text', text: replacedWith((o) => { o.version = '1'; }), reason: 'version' },
  { id: 'version-missing', text: replacedWith((o) => { delete o.version; }), reason: 'version' },
  { id: 'extra-member', text: replacedWith((o) => { o.extra = null; }), reason: 'form' },
  { id: 'forget-missing', text: replacedWith((o) => { delete o.forget; }), reason: 'form' },
  { id: 'keys-array', text: replacedWith((o) => { o.keys = []; }), reason: 'form' },
  { id: 'entries-null', text: replacedWith((o) => { o.entries = null; }), reason: 'form' },
  { id: 'forget-object', text: replacedWith((o) => { o.forget = {}; }), reason: 'form' },
  { id: 'policy-unknown', text: replacedWith((o) => { o.keys = { Unattended: KEY(o) }; }), reason: 'form' },
  { id: 'key-pending-missing', text: replacedWith((o) => { delete KEY(o).pending; }), reason: 'form' },
  { id: 'key-extra-member', text: replacedWith((o) => { KEY(o).label = 'x'; }), reason: 'form' },
  { id: 'backend-unknown', text: replacedWith((o) => { KEY(o).backend = 'keychain'; }), reason: 'form' },
  { id: 'item-uppercase', text: replacedWith((o) => { KEY(o).item = ITEM.B.toUpperCase(); }), reason: 'form' },
  { id: 'item-short', text: replacedWith((o) => { KEY(o).item = ITEM.B.slice(1); }), reason: 'form' },
  { id: 'item-number', text: replacedWith((o) => { KEY(o).item = 1; }), reason: 'form' },
  { id: 'key-with-neither', text: replacedWith((o) => { o.keys.user_presence = { backend: mk, item: null, sealed: null, pending: null }; }), reason: 'form' },
  { id: 'pending-item-missing', text: sevenWith((o) => { delete o.keys.user_presence.pending.item; }), reason: 'form' },
  { id: 'pending-item-null', text: sevenWith((o) => { o.keys.user_presence.pending.item = null; }), reason: 'form' },
  { id: 'pending-extra-member', text: sevenWith((o) => { o.keys.user_presence.pending.sealed = null; }), reason: 'form' },
  { id: 'pending-only-other-backend', text: sevenWith((o) => { o.keys.user_presence.backend = ss; }), reason: 'form' },
  { id: 'keychain-sealed', text: replacedWith((o) => { KEY(o).sealed = BLOB1; }), reason: 'form' },
  { id: 'secret-service-sealed', text: withObject(S.copied, (o) => { KEY(o).sealed = BLOB1; }), reason: 'form' },
  { id: 'dpapi-sealed-null', text: dpapiWith((o) => { KEY(o).sealed = null; }), reason: 'form' },
  { id: 'dpapi-sealed-unpadded', text: dpapiWith((o) => { KEY(o).sealed = BLOB1.replace(/=+$/, ''); }), reason: 'form' },
  { id: 'dpapi-sealed-empty', text: dpapiWith((o) => { KEY(o).sealed = ''; }), reason: 'form' },
  { id: 'dpapi-sealed-over-bound', text: dpapiWith((o) => { KEY(o).sealed = b64(Buffer.alloc(MAX_BLOB_BYTES + 1, 1)); }), reason: 'form' },
  { id: 'dpapi-sealed-trailing-bits', text: dpapiWith((o) => { KEY(o).sealed = 'AR=='; }), reason: 'form' },
  { id: 'dpapi-pending-only-sealed', text: withObject(S.dpapiPending, (o) => { KEY(o).sealed = BLOB1; }), reason: 'form' },
  { id: 'forget-dpapi', text: replacedWith((o) => { o.forget[0].backend = dp; }), reason: 'form' },
  { id: 'forget-policy-missing', text: replacedWith((o) => { delete o.forget[0].policy; }), reason: 'form' },
  { id: 'forget-policy-unknown', text: replacedWith((o) => { o.forget[0].policy = 'presence'; }), reason: 'form' },
  { id: 'forget-null-record', text: replacedWith((o) => { o.forget.push(null); }), reason: 'form' },
  { id: 'name-uppercase', text: replacedWith((o) => { o.entries = { 'Quick-unlock': ENTRY(o) }; }), reason: 'form' },
  { id: 'name-digit-first', text: replacedWith((o) => { o.entries = { '1quick': ENTRY(o) }; }), reason: 'form' },
  { id: 'name-too-long', text: replacedWith((o) => { o.entries = { ['q'.repeat(MAX_NAME_BYTES + 1)]: ENTRY(o) }; }), reason: 'form' },
  { id: 'entry-binding-missing', text: replacedWith((o) => { delete ENTRY(o).binding; }), reason: 'form' },
  { id: 'entry-key-unknown', text: replacedWith((o) => { ENTRY(o).key = 'other'; }), reason: 'form' },
  { id: 'nonce-11-bytes', text: replacedWith((o) => { ENTRY(o).nonce = sevenNonce(11); }), reason: 'form' },
  { id: 'nonce-13-bytes', text: replacedWith((o) => { ENTRY(o).nonce = sevenNonce(13); }), reason: 'form' },
  { id: 'nonce-unpadded', text: replacedWith((o) => { ENTRY(o).nonce = b64(Buffer.alloc(11, 7)).replace(/=+$/, ''); }), reason: 'form' },
  { id: 'ciphertext-tag-only', text: replacedWith((o) => { ENTRY(o).ciphertext = ciphertextOf(16); }), reason: 'form' },
  { id: 'ciphertext-over-bound', text: replacedWith((o) => { ENTRY(o).ciphertext = ciphertextOf(MAX_SECRET_BYTES + 16 + 1); }), reason: 'form' },
  { id: 'ciphertext-trailing-bits', text: replacedWith((o) => { ENTRY(o).ciphertext = `${ciphertextOf(17).slice(0, -3)}B==`; }), reason: 'form' },
  { id: 'binding-number', text: replacedWith((o) => { ENTRY(o).binding = { vault_sha256: 1 }; }), reason: 'form' },
  { id: 'binding-member-uppercase', text: replacedWith((o) => { ENTRY(o).binding = { Vault: VAULT1 }; }), reason: 'form' },
  { id: 'binding-value-empty', text: replacedWith((o) => { ENTRY(o).binding = { vault_sha256: '' }; }), reason: 'form' },
  { id: 'binding-value-control', text: replacedWith((o) => { ENTRY(o).binding = { vault_sha256: 'a\tb' }; }), reason: 'form' },
  { id: 'binding-value-unicode', text: replacedWith((o) => { ENTRY(o).binding = { vault_sha256: 'café' }; }), reason: 'form' },
  { id: 'binding-value-too-long', text: replacedWith((o) => { ENTRY(o).binding = { vault_sha256: 'v'.repeat(MAX_BINDING_VALUE_BYTES + 1) }; }), reason: 'form' },
  { id: 'binding-five-members', text: replacedWith((o) => { ENTRY(o).binding = { a: '1', b: '2', c: '3', d: '4', e: '5' }; }), reason: 'form' },
  { id: 'binding-array', text: replacedWith((o) => { ENTRY(o).binding = []; }), reason: 'form' },
  {
    id: 'forget-five-records',
    text: replacedWith((o) => { o.forget = [ITEM.C, ITEM.D, ITEM.E, ITEM.F, ITEM.G].map((item) => fr(mk, 'unattended', item)); }),
    reason: 'items',
  },
  { id: 'five-items', text: sevenWith((o) => { o.forget.push(fr(mk, 'unattended', ITEM.E)); }), reason: 'items' },
  {
    id: 'thirty-three-entries',
    text: withObject(S.maxEntries, (o) => {
      o.entries.f = { key: 'unattended', nonce: b64(nonceFor('f')), ciphertext: ciphertextOf(17), binding: {} };
    }),
    reason: 'entries',
  },
  { id: 'item-in-key-and-forget', text: replacedWith((o) => { o.forget[0].item = ITEM.B; }), reason: 'duplicate' },
  { id: 'pending-is-the-item', text: replacedWith((o) => { KEY(o).pending = { backend: mk, item: ITEM.B }; }), reason: 'duplicate' },
  { id: 'item-twice-in-forget', text: replacedWith((o) => { o.forget.push(fr(mk, 'user_presence', ITEM.A)); }), reason: 'duplicate' },
  { id: 'nonce-twice-under-a-key', text: replacedWith((o) => { o.entries['rpc-api-key.alchemy'].nonce = ENTRY(o).nonce; }), reason: 'duplicate' },
  { id: 'entry-under-no-key', text: replacedWith((o) => { ENTRY(o).key = 'user_presence'; }), reason: 'key_not_in_use' },
  { id: 'entry-under-a-pending-key', text: sevenWith((o) => { ENTRY(o).key = 'user_presence'; }), reason: 'key_not_in_use' },
  { id: 'key-with-no-entry', text: replacedWith((o) => { o.entries = {}; }), reason: 'key_unused' },
  { id: 'compact', text: JSON.stringify(base()), reason: 'not_canonical' },
  { id: 'newline-after', text: `${textOf(base())}\n`, reason: 'not_canonical' },
  { id: 'four-spaces', text: JSON.stringify(base(), null, 4), reason: 'not_canonical' },
  { id: 'version-1.0', text: replaceText(textOf(base()), '"version": 1,', '"version": 1.0,'), reason: 'not_canonical' },
  { id: 'version-twice', text: replaceText(textOf(base()), '"version": 1,', '"version": 1,\n  "version": 1,'), reason: 'not_canonical' },
  { id: 'escaped-name', text: replaceText(textOf(base()), '"quick-unlock": {', '"\\u0071uick-unlock": {'), reason: 'not_canonical' },
  {
    id: 'entries-out-of-order',
    text: replacedWith((o) => { o.entries = { 'rpc-api-key.alchemy': o.entries['rpc-api-key.alchemy'], 'quick-unlock': ENTRY(o) }; }),
    reason: 'not_canonical',
  },
  {
    id: 'keys-out-of-order',
    text: withObject(S.twoKeys, (o) => { o.keys = { user_presence: o.keys.user_presence, unattended: o.keys.unattended }; }),
    reason: 'not_canonical',
  },
  {
    id: 'key-members-out-of-order',
    text: replacedWith((o) => { const k = KEY(o); o.keys.unattended = { item: k.item, backend: k.backend, sealed: k.sealed, pending: k.pending }; }),
    reason: 'not_canonical',
  },
  {
    id: 'binding-out-of-order',
    text: withObject({ ...S.enrolled, entries: { 'quick-unlock': entry('unattended', 'k1', 'n1', 'p', { a: '1', b: '2' }) } },
      (o) => { ENTRY(o).binding = { b: '2', a: '1' }; }),
    reason: 'not_canonical',
  },
];

// ---------------------------------------------------------------------------
// Transitions

const N = (label) => hex(nonceFor(label));
const K = (label) => hex(WRAP[label]);
const sealedOf = (backend, policy, item, blobText = null) => ({ backend, policy, item, blob: blobText });
const putOf = (name, binding, secret) => ({ name, binding, secret });
const QUICK = putOf('quick-unlock', QB, 'correct horse battery staple');

const T = (id, before, op, rng, outcome) => ({ id, before, op, rng, outcome });
const TRANSITIONS = [
  // A first key: pending, then committed with its entry.
  T('begin-first', S.empty, ['begin_create', 'unattended', mk, ITEM.A], [], { after: S.pendingA }),
  T('commit-first', S.pendingA, ['commit', sealedOf(mk, 'unattended', ITEM.A), K('k1'), null, QUICK], [N('n1')], { after: S.enrolled }),
  T('commit-first-nothing-to-put', S.pendingA, ['commit', sealedOf(mk, 'unattended', ITEM.A), K('k1'), null, null], [], { refused: 'no_entry' }),
  T('commit-other-item', S.pendingA, ['commit', sealedOf(mk, 'unattended', ITEM.B), K('k1'), null, QUICK], [N('n1')], { refused: 'not_pending' }),
  T('commit-other-policy', S.pendingA, ['commit', sealedOf(mk, 'user_presence', ITEM.A), K('k1'), null, QUICK], [N('n1')], { refused: 'not_pending' }),
  T('commit-other-backend', S.pendingA, ['commit', sealedOf(ss, 'unattended', ITEM.A), K('k1'), null, QUICK], [N('n1')], { refused: 'not_pending' }),
  T('commit-no-pending', S.enrolled, ['commit', sealedOf(mk, 'unattended', ITEM.A), K('k1'), K('k1'), null], [], { refused: 'not_pending' }),
  T('commit-empty-secret', S.pendingA, ['commit', sealedOf(mk, 'unattended', ITEM.A), K('k1'), null, putOf('quick-unlock', QB, '')], [N('n1')], { refused: 'secret_size' }),
  T('commit-rng-fails', S.pendingA, ['commit', sealedOf(mk, 'unattended', ITEM.A), K('k1'), null, QUICK], [], { refused: 'randomness' }),
  // A second entry: the first draw repeats a nonce under the key, so it is drawn again.
  T('put-second-nonce-redrawn', S.enrolled, ['put', 'unattended', K('k1'), putOf('rpc-api-key.alchemy', {}, 'alchemy-api-key-0123')], [N('n1'), N('n2')], { after: S.twoEntries }),
  T('put-nonce-stuck', S.enrolled, ['put', 'unattended', K('k1'), putOf('rpc-api-key.alchemy', {}, 'x')], [N('n1'), N('n1'), N('n1'), N('n1')], { refused: 'randomness' }),
  T('put-no-key', S.enrolled, ['put', 'user_presence', K('k1'), putOf('export', {}, 'x')], [N('n2')], { refused: 'no_key' }),
  T('put-pending-key', S.pendingA, ['put', 'unattended', K('k1'), putOf('export', {}, 'x')], [N('n2')], { refused: 'no_key' }),
  T('put-secret-over-bound', S.enrolled, ['put', 'unattended', K('k1'), putOf('export', {}, 'x'.repeat(MAX_SECRET_BYTES + 1))], [N('n2')], { refused: 'secret_size' }),
  T('put-other-key', S.twoKeys, ['put', 'user_presence', K('k2'), putOf('quick-unlock', QB, 'x')], [N('n2')], { refused: 'other_key' }),
  T('put-past-max-entries', S.maxEntries, ['put', 'unattended', K('k1'), putOf('f', {}, 'x')], [N('n2')], { refused: 'entries' }),
  // A replace draws a nonce no entry under the key holds, its own old one included.
  T('put-replaces-at-max-entries', S.maxEntries, ['put', 'unattended', K('k1'), putOf('e31', {}, 'secret 31 again')], [N('e31'), N('r31')], { after: S.maxEntriesReplaced }),
  // A replace: pending, then committed with every entry re-wrapped, the old key recorded.
  T('begin-replace', S.twoEntries, ['begin_create', 'unattended', mk, ITEM.B], [], { after: S.replacing }),
  T('commit-replace', S.replacing, ['commit', sealedOf(mk, 'unattended', ITEM.B), K('k2'), K('k1'), null], [N('n3'), N('n4')], { after: S.replaced }),
  T('commit-replace-wrong-old-key', S.replacing, ['commit', sealedOf(mk, 'unattended', ITEM.B), K('k2'), K('k3'), null], [N('n3'), N('n4')], { refused: 'entry_refused' }),
  T('commit-replace-no-old-key', S.replacing, ['commit', sealedOf(mk, 'unattended', ITEM.B), K('k2'), null, null], [N('n3'), N('n4')], { refused: 'key_needed' }),
  // To the bound: an earlier pending item of the policy moves into forget.
  T('begin-other-policy', S.replaced, ['begin_create', 'user_presence', mk, ITEM.C], [], { after: S.pendingC }),
  T('begin-again-moves-pending', S.pendingC, ['begin_create', 'user_presence', mk, ITEM.D], [], { after: S.full }),
  T('begin-fifth-refused', S.full, ['begin_create', 'unattended', mk, ITEM.E], [], { refused: 'forget_backlog' }),
  T('begin-fifth-replacing-pending-refused', S.full, ['begin_create', 'user_presence', mk, ITEM.E], [], { refused: 'forget_backlog' }),
  T('begin-named-refused', S.full, ['begin_create', 'unattended', mk, ITEM.C], [], { refused: 'named' }),
  T('begin-named-pending-refused', S.pendingC, ['begin_create', 'unattended', mk, ITEM.C], [], { refused: 'named' }),
  T('forgotten', S.full, ['forgotten', ITEM.A], [], { after: S.afterForgetA }),
  T('forgotten-unlisted', S.afterForgetA, ['forgotten', ITEM.E], [], { after: S.afterForgetA }),
  T('forgotten-key-in-use', S.afterForgetA, ['forgotten', ITEM.B], [], { after: S.afterForgetA }),
  T('begin-after-forget', S.afterForgetA, ['begin_create', 'unattended', mk, ITEM.E], [], { after: S.fullAgain }),
  // At open: pending items move into forget, in order of policy.
  T('settle', S.fullAgain, ['settle'], [], { after: S.settled }),
  T('settle-nothing-pending', S.settled, ['settle'], [], { after: S.settled }),
  // Removing entries: the last one under a key takes the key into forget.
  T('remove-one', S.settled, ['remove', 'rpc-api-key.alchemy'], [], { after: S.oneLeft }),
  T('remove-last', S.oneLeft, ['remove', 'quick-unlock'], [], { after: S.allForgotten }),
  T('remove-missing', S.allForgotten, ['remove', 'quick-unlock'], [], { refused: 'no_entry' }),
  // Records of a backend this OS doesn't have.
  T('drop-foreign', S.copied, ['drop_foreign', ss], [], { after: S.copiedNative }),
  T('drop-foreign-no-key-store', S.copied, ['drop_foreign', null], [], { after: S.copiedNone }),
  // DPAPI: the blob is kept with the key, and no record is ever made.
  T('dpapi-begin', S.empty, ['begin_create', 'unattended', dp, ITEM.F], [], { after: S.dpapiPending }),
  T('dpapi-commit', S.dpapiPending, ['commit', sealedOf(dp, 'unattended', ITEM.F, BLOB1), K('k3'), null, putOf('bee-password', { keystore_sha256: KEYSTORE1 }, 'bee-keystore-password')], [N('n6')], { after: S.dpapi }),
  T('dpapi-begin-replace', S.dpapi, ['begin_create', 'unattended', dp, ITEM.G], [], { after: S.dpapiReplacing }),
  T('dpapi-commit-replace', S.dpapiReplacing, ['commit', sealedOf(dp, 'unattended', ITEM.G, BLOB2), K('k4'), K('k3'), null], [N('n7')], { after: S.dpapiReplaced }),
  T('dpapi-commit-committed-item', S.dpapiReplacing, ['commit', sealedOf(dp, 'unattended', ITEM.F, BLOB2), K('k4'), K('k3'), null], [N('n7')], { refused: 'not_pending' }),
  T('dpapi-settle', S.dpapiPendingAgain, ['settle'], [], { after: S.dpapiReplaced }),
  T('dpapi-remove-last', S.dpapiReplaced, ['remove', 'bee-password'], [], { after: S.empty }),
  T('pending-only-switches-backend', S.dpapiPending, ['begin_create', 'unattended', ss, ITEM.H], [], { after: S.switchedPending }),
  T('dpapi-begin-keychain', S.dpapi, ['begin_create', 'unattended', mk, ITEM.H], [], { after: S.dpapiToKeychain }),
  T('dpapi-replaced-by-keychain', S.dpapiToKeychain, ['commit', sealedOf(mk, 'unattended', ITEM.H), K('k5'), K('k3'), null], [N('n8')], { after: S.keychainFromDpapi }),
];

// ---------------------------------------------------------------------------

function buildSecrets(meta) {
  const files = FILES.map(({ id, state, opens }) => ({
    id, text: fileText(state), items: itemsOf(state), entries: entriesOf(state), opens,
  }));
  const ids = new Set();
  for (const { id } of [...FILES, ...MALFORMED, ...TRANSITIONS]) {
    assert.ok(!ids.has(id), `duplicate id ${id}`);
    ids.add(id);
  }
  for (const file of files) {
    assert.ok(Buffer.byteLength(file.text) <= MAX_FILE_BYTES, file.id);
    assert.ok(file.items.length <= MAX_ITEMS, file.id);
  }
  for (const m of MALFORMED) {
    assert.equal(['text', 'text_hex', 'text_repeat'].filter((k) => k in m).length, 1, m.id);
    assert.ok(FORMATS.malformed.includes(`${m.reason} (`), m.id);
  }
  const transitions = TRANSITIONS.map(({ id, before, op, rng, outcome }) => {
    for (const draw of rng) assert.match(draw, /^[0-9a-f]{24}$/, id);
    assert.equal(Object.keys(outcome).length, 1, id);
    const out = { id, before: fileText(before), op, rng };
    if (outcome.after) {
      out.after = fileText(outcome.after);
      out.after_items = itemsOf(outcome.after);
    } else {
      assert.ok(FORMATS.transitions.includes(outcome.refused), id);
      out.refused = outcome.refused;
    }
    return out;
  });
  return {
    meta,
    source: 'design 0013 (5.4a: The secrets file, The failure contract, Forgetting an item, The bounds): every case and outcome is the design\'s, written by hand in vectors/generator/secrets.js; no reference implementation exists. The generator lays each file out and seals each entry with Node\'s AES-256-GCM under fixed keys and nonces, which are public test values.',
    formats: FORMATS,
    constants: {
      version: VERSION, aad_label: AAD_LABEL, policies: POLICIES, backends: BACKENDS, max_items: MAX_ITEMS,
      max_entries: MAX_ENTRIES, max_name_bytes: MAX_NAME_BYTES, max_secret_bytes: MAX_SECRET_BYTES,
      max_binding_members: MAX_BINDING_MEMBERS, max_binding_name_bytes: MAX_BINDING_NAME_BYTES,
      max_binding_value_bytes: MAX_BINDING_VALUE_BYTES, max_blob_bytes: MAX_BLOB_BYTES, max_file_bytes: MAX_FILE_BYTES,
      nonce_bytes: 12, tag_bytes: 16,
    },
    files,
    malformed: MALFORMED,
    transitions,
  };
}

module.exports = { buildSecrets };
