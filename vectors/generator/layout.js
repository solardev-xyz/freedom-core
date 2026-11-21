'use strict';

// The Freedom directory's move (design 0013, 5.4b: "What moves", "The
// move"; PRF-9a). No reference implementation exists: no build of the
// browser writes the move's journal, and the browser keeps only a copy of
// the list (src/main/freedom-root.js, checked against this file from B3).
// So every case and every outcome here is the design's, written out by hand
// below as plain rows; nothing is computed by a model of the rules.
// fc-profile's tests replay them (crates/fc-profile/tests/layout.rs).
//
// The generator only lays the rows out: it names each one, writes each
// journal a move writes as JSON.stringify({ version: 2, entries, copied }),
// and checks every row's shape (names, kinds, outcomes), so a typo fails
// generation instead of passing as an expectation.
//
// The formats are in the file's `formats` member.

const assert = require('node:assert/strict');

const CONSTANTS = {
  freedom_dir: 'freedom',
  move_journal: '.move.json',
  layout_marker: 'layout.json',
  moving_suffix: '.moving',
  placeholder: 'identity',
  max_journal_bytes: 16 * 1024,
};

// What moves into `freedom/`, in the order a move takes them.
const MOVED_ENTRIES = [
  'identity',
  // Set A.
  'wallet-intents.jsonl',
  'safe-pending.json',
  'dapp-permissions.json',
  'swarm-permissions.json',
  'radicle-permissions.json',
  'x402-permissions.json',
  'phone-payments.json',
  'swarm-feeds.json',
  'swarm-manifest-grants.json',
  'rpc-api-keys.json',
  'payment-history.sqlite',
  'payment-history.sqlite-wal',
  'payment-history.sqlite-shm',
  'publish-history.sqlite',
  'publish-history.sqlite-wal',
  'publish-history.sqlite-shm',
  // Set B.
  'settings.json',
  'network-config.json',
  'custom-chains.json',
  'custom-tokens.json',
  'permissions.json',
  'adblock-allowlist.json',
  'external-node-decisions.json',
  'balance-cache.json',
  'chain-catalog.json',
  'swarm-browsing-credit.json',
  // The nodes' data, and antd's hand-off.
  'ant-data',
  'ipfs-data',
  'tor-data',
  'myotis',
  'bee-data',
  'run',
];

const KINDS = ['missing', 'file', 'dir', 'other'];
const STEPS = ['remove_moving', 'remove_moved', 'remove_placeholder', 'rename_back'];
const UNSETTLED = ['moving_without_source', 'source_gone', 'at_both', 'not_moved', 'nowhere'];
const DEFERRALS = ['node_identity_journal', 'freedom_not_dir', 'freedom_holds', 'mount_point'];

const FORMATS = {
  constants: 'The names under a profile\'s directory: `freedom_dir` (the Freedom directory), and in it `move_journal`, `layout_marker` and `<name><moving_suffix>` (a cross-device copy before its rename); `placeholder`, the root\'s entry a regular file takes after the marker; `max_journal_bytes`, the largest journal read.',
  moved_entries: 'What moves into `freedom/`, in the order a move takes them. A name not listed stays at the root.',
  journals: 'Journal texts as recovery reads them: `text`, then either `entries` and `copied` (in form; a version 1 journal has `copied` empty) or `malformed: true` (the profile stays closed). Keys are exact and each appears once; names are in `moved_entries` and appear once in each list; `copied` is within `entries`.',
  written: 'The text a move writes for `entries` and `copied`: always version 2, `JSON.stringify({ version: 2, entries, copied })` (no white space, no newline). It is written again, with a name added to `copied`, before that entry\'s copy begins.',
  state: 'An entry\'s state: [at_root, in_freedom, moving], what is at `<name>`, `freedom/<name>` and `freedom/<name>.moving`, each missing, file, dir or other (looked at as lstat does: a symlink is other).',
  rollback: 'Before the marker: { id, name, copied, state, then `steps` or `unsettled` }. `steps`, in the order they run, are those of remove_moving (freedom/<name>.moving), remove_moved (freedom/<name>, a copied entry\'s copy), remove_placeholder (the file at the root\'s identity) and rename_back (freedom/<name> to the root) that apply; an empty list is nothing to do. Entries are rolled back in the journal\'s reverse order. `unsettled`: moving_without_source, source_gone, at_both, not_moved or nowhere: the run changes nothing and the profile stays closed (corrupt).',
  roll_forward: 'After the marker: { id, copied, state, then `remove_source` (whether what is at the root goes: a copied entry\'s source, perhaps half removed) or `unsettled` }.',
  placeholder: 'After the roll-forward\'s removals: { identity_at_root, needed }: the placeholder is written only where nothing is.',
  plan_start: 'Whether a starting move starts: { id, root: { <name>: { found, mount_point } } (what is at each name of moved_entries at the root; a name left out is missing, one not in the list ignored), freedom: null (missing), "other" (not a directory) or the names in it, node_identity_journal (one pending in identity/), then `moves` (the entries the journal names, in the list\'s order; empty for an empty move) or `deferred`: { reason, name? } }. The first reason found, in this order: node_identity_journal; freedom_not_dir; freedom_holds (a name in freedom/ the move writes, compared case-folded and without trailing dots and spaces: its name as found); mount_point (the first in the list\'s order).',
};

// ---------------------------------------------------------------------------
// The rows, by hand.

const J = (version, entries, copied) => {
  const object = { version, entries };
  if (copied !== undefined) object.copied = copied;
  return JSON.stringify(object);
};

// In form: [text, entries, copied].
const JOURNALS_IN_FORM = [
  ['{"version":1,"entries":["identity","ipfs-data"]}', ['identity', 'ipfs-data'], []],
  ['{ "entries": [], "version": 1 }', [], []],
  ['{"version":2,"entries":["identity","ant-data","run"],"copied":["run","ant-data"]}', ['identity', 'ant-data', 'run'], ['run', 'ant-data']],
  ['{"copied":[],"entries":["run"],"version":2}', ['run'], []],
  ['{"version":2,"entries":[],"copied":[]}', [], []],
  ['{"version":2.0,"entries":["payment-history.sqlite","payment-history.sqlite-wal"],"copied":[]}', ['payment-history.sqlite', 'payment-history.sqlite-wal'], []],
  ['{"version":2,"entries":["\\u0069dentity"],"copied":["identity"]}', ['identity'], ['identity']],
];

const JOURNALS_MALFORMED = [
  '',
  'not json',
  '[]',
  '{"version":1}',
  '{"entries":[]}',
  '{"version":3,"entries":[],"copied":[]}',
  '{"version":"2","entries":[],"copied":[]}',
  '{"version":1,"entries":[],"copied":[]}',
  '{"version":2,"entries":["run"]}',
  '{"version":2,"entries":[],"copied":[],"extra":true}',
  '{"version":2,"entries":["run"],"copied":"run"}',
  '{"version":2,"entries":["Profiles"],"copied":[]}',
  '{"version":2,"entries":["run"],"copied":["Profiles"]}',
  '{"version":2,"entries":["run","run"],"copied":[]}',
  '{"version":2,"entries":["run"],"copied":["run","run"]}',
  '{"version":2,"entries":["run"],"copied":["ant-data"]}',
  '{"version":2,"entries":["run"],"copied":["run.moving"]}',
  '{"version":1,"entries":["identity"],"entries":[]}',
  '{"version":2,"entries":["run"],"copied":[],"copied":["run"]}',
  '{"version":2,"entries":["run"],"copied":[],"c\\u006fpied":["run"]}',
  '{"version":1,"entries":["../identity"]}',
  '{"version":1,"entries":["freedom"]}',
  '{"version":1,"entries":["Identity"]}',
];

// [entries, copied]: the journals a move writes, in turn.
const WRITTEN = [
  [[], []],
  [['identity', 'settings.json', 'ant-data'], []],
  [['identity', 'settings.json', 'ant-data'], ['ant-data']],
  [MOVED_ENTRIES, []],
];

const m = 'missing';
const f = 'file';
const d = 'dir';
const o = 'other';

// Before the marker: [name, copied, state, steps (array) or unsettled].
const ROLLBACK = [
  // Every cell of presence, each place a directory, renamed then copied.
  ['ant-data', false, [m, m, m], 'nowhere'],
  ['ant-data', true, [m, m, m], 'nowhere'],
  ['ant-data', false, [d, m, m], []],
  ['ant-data', true, [d, m, m], []],
  ['ant-data', false, [m, d, m], ['rename_back']],
  ['ant-data', true, [m, d, m], 'source_gone'],
  ['ant-data', false, [d, d, m], 'at_both'],
  ['ant-data', true, [d, d, m], ['remove_moved']],
  ['ant-data', false, [m, m, d], 'moving_without_source'],
  ['ant-data', true, [m, m, d], 'moving_without_source'],
  ['ant-data', false, [d, m, d], ['remove_moving']],
  ['ant-data', true, [d, m, d], ['remove_moving']],
  ['ant-data', false, [m, d, d], 'moving_without_source'],
  ['ant-data', true, [m, d, d], 'moving_without_source'],
  ['ant-data', false, [d, d, d], 'at_both'],
  ['ant-data', true, [d, d, d], ['remove_moving', 'remove_moved']],
  // The placeholder beside the moved directory (a version 1 journal's
  // order): only for identity, a file beside a directory, never copied.
  ['identity', false, [f, d, m], ['remove_placeholder', 'rename_back']],
  ['identity', false, [f, d, d], ['remove_moving', 'remove_placeholder', 'rename_back']],
  ['identity', true, [f, d, m], 'source_gone'],
  ['identity', false, [f, f, m], 'at_both'],
  ['identity', false, [d, d, m], 'at_both'],
  ['identity', false, [o, d, m], 'at_both'],
  ['settings.json', false, [f, d, m], 'at_both'],
  ['settings.json', false, [f, f, m], 'at_both'],
  ['settings.json', false, [f, m, m], []],
  // Kinds: a link moved as itself; a copied entry's copies of its kind.
  ['tor-data', false, [m, o, m], ['rename_back']],
  ['tor-data', true, [o, o, m], ['remove_moved']],
  ['settings.json', true, [f, f, f], ['remove_moving', 'remove_moved']],
  ['ant-data', true, [f, d, m], 'source_gone'],
  ['ant-data', true, [o, d, m], 'source_gone'],
  ['ant-data', true, [d, o, m], 'source_gone'],
  ['ant-data', true, [f, m, d], 'source_gone'],
  ['ant-data', true, [d, d, f], 'source_gone'],
  ['payment-history.sqlite-wal', false, [m, f, m], ['rename_back']],
];

// After the marker: [copied, state, remove_source (boolean) or unsettled].
const ROLL_FORWARD = [
  // Every cell of presence, each place a directory, renamed then copied.
  [false, [m, m, m], 'nowhere'],
  [true, [m, m, m], 'nowhere'],
  [false, [d, m, m], 'not_moved'],
  [true, [d, m, m], 'not_moved'],
  [false, [m, d, m], false],
  [true, [m, d, m], false],
  [false, [d, d, m], false],
  [true, [d, d, m], true],
  [false, [m, m, d], 'not_moved'],
  [true, [m, m, d], 'not_moved'],
  [false, [d, m, d], 'not_moved'],
  [true, [d, m, d], 'not_moved'],
  [false, [m, d, d], 'not_moved'],
  [true, [m, d, d], 'not_moved'],
  [false, [d, d, d], 'not_moved'],
  [true, [d, d, d], 'not_moved'],
  // The placeholder beside the moved directory stays, copied or not.
  [false, [f, d, m], false],
  [true, [f, d, m], false],
  // A copied source of its copy's kind goes; another kind isn't the source.
  [true, [f, f, m], true],
  [true, [o, o, m], true],
  [true, [o, d, m], false],
  [true, [d, o, m], false],
  // A renamed entry's residue stays, whatever its kind.
  [false, [f, f, m], false],
  [false, [o, d, m], false],
  // A copy still in progress after the marker.
  [false, [d, d, f], 'not_moved'],
  [true, [f, f, f], 'not_moved'],
];

// [identity_at_root, needed].
const PLACEHOLDER = [[m, true], [f, false], [d, false], [o, false]];

const at = (found, mountPoint = false) => ({ found, mount_point: mountPoint });

// [id, root, freedom, node_identity_journal, { moves } | { deferred }].
const PLAN_START = [
  ['new-profile', {}, null, false, { moves: [] }],
  ['present-in-the-lists-order', {
    run: at(d), 'settings.json': at(f), identity: at(d), 'tor-data': at(o), 'ipfs-data': at(m),
    'payment-history.sqlite-wal': at(f), 'payment-history.sqlite': at(f), Cookies: at(f), 'radicle-data': at(d),
  }, null, false, { moves: ['identity', 'payment-history.sqlite', 'payment-history.sqlite-wal', 'settings.json', 'tor-data', 'run'] }],
  ['freedom-holding-other-names', { identity: at(d) }, ['notes.txt', '.move.json.tmp', 'identity-old'], false, { moves: ['identity'] }],
  ['freedom-empty', { identity: at(d) }, [], false, { moves: ['identity'] }],
  ['mount-point-missing', { 'ant-data': at(m, true) }, null, false, { moves: [] }],
  ['node-identity-journal', { identity: at(d), 'ant-data': at(d, true) }, 'other', true, { deferred: { reason: 'node_identity_journal' } }],
  ['freedom-not-a-directory', { identity: at(d), 'ant-data': at(d, true) }, 'other', false, { deferred: { reason: 'freedom_not_dir' } }],
  ['freedom-holds-an-entry', { identity: at(d) }, ['notes.txt', 'IDENTITY'], false, { deferred: { reason: 'freedom_holds', name: 'IDENTITY' } }],
  ['freedom-holds-a-folded-entry', { identity: at(d) }, ['ſettings.json'], false, { deferred: { reason: 'freedom_holds', name: 'ſettings.json' } }],
  ['freedom-holds-a-moving-copy', { identity: at(d) }, ['ant-data.moving'], false, { deferred: { reason: 'freedom_holds', name: 'ant-data.moving' } }],
  ['freedom-holds-the-journal', { identity: at(d) }, ['.move.json'], false, { deferred: { reason: 'freedom_holds', name: '.move.json' } }],
  ['freedom-holds-the-marker', { identity: at(d) }, ['Layout.JSON'], false, { deferred: { reason: 'freedom_holds', name: 'Layout.JSON' } }],
  ['freedom-holds-trailing-dots', { identity: at(d) }, ['run. .'], false, { deferred: { reason: 'freedom_holds', name: 'run. .' } }],
  ['mount-points', { identity: at(d), 'ipfs-data': at(d, true), 'ant-data': at(d, true) }, null, false, { deferred: { reason: 'mount_point', name: 'ant-data' } }],
];

// ---------------------------------------------------------------------------
// Laying the rows out.

const isName = (name) => MOVED_ENTRIES.includes(name);

function checkState(state, id) {
  assert.ok(Array.isArray(state) && state.length === 3 && state.every((k) => KINDS.includes(k)), `state ${id}`);
}

const stateId = (state) => state.join('-');

function buildLayout(meta) {
  assert.equal(new Set(MOVED_ENTRIES).size, MOVED_ENTRIES.length, 'moved entries once');
  for (const name of MOVED_ENTRIES) assert.match(name, /^[a-z][a-z0-9.-]*$/, name);

  const journals = [];
  for (const [text, entries, copied] of JOURNALS_IN_FORM) {
    assert.ok(entries.every(isName) && copied.every((name) => entries.includes(name)), text);
    journals.push({ text, entries, copied });
  }
  for (const text of JOURNALS_MALFORMED) journals.push({ text, malformed: true });
  assert.equal(new Set(journals.map((j) => j.text)).size, journals.length, 'journal texts once');

  const written = WRITTEN.map(([entries, copied]) => {
    assert.ok(entries.every(isName) && copied.every((name) => entries.includes(name)), 'written');
    return { entries, copied, text: J(2, entries, copied) };
  });

  const rollback = ROLLBACK.map(([name, copied, state, outcome]) => {
    assert.ok(isName(name), name);
    const id = `${name}-${copied ? 'copied' : 'renamed'}-${stateId(state)}`;
    checkState(state, id);
    const row = { id, name, copied, state };
    if (Array.isArray(outcome)) {
      assert.deepEqual(outcome, STEPS.filter((step) => outcome.includes(step)), `steps in order ${id}`);
      row.steps = outcome;
    } else {
      assert.ok(UNSETTLED.includes(outcome), id);
      row.unsettled = outcome;
    }
    return row;
  });
  assert.equal(new Set(rollback.map((r) => r.id)).size, rollback.length, 'rollback ids once');

  const rollForward = ROLL_FORWARD.map(([copied, state, outcome]) => {
    const id = `${copied ? 'copied' : 'renamed'}-${stateId(state)}`;
    checkState(state, id);
    const row = { id, copied, state };
    if (typeof outcome === 'boolean') row.remove_source = outcome;
    else {
      assert.ok(UNSETTLED.includes(outcome), id);
      row.unsettled = outcome;
    }
    return row;
  });
  assert.equal(new Set(rollForward.map((r) => r.id)).size, rollForward.length, 'roll-forward ids once');

  const placeholder = PLACEHOLDER.map(([identityAtRoot, needed]) => {
    assert.ok(KINDS.includes(identityAtRoot));
    return { identity_at_root: identityAtRoot, needed };
  });

  const planStart = PLAN_START.map(([id, root, freedom, nodeIdentityJournal, outcome]) => {
    for (const value of Object.values(root)) {
      assert.ok(KINDS.includes(value.found) && typeof value.mount_point === 'boolean', id);
    }
    assert.ok(freedom === null || freedom === 'other' || (Array.isArray(freedom) && freedom.every((n) => typeof n === 'string')), id);
    const row = { id, root, freedom, node_identity_journal: nodeIdentityJournal };
    if (outcome.moves) {
      assert.ok(outcome.moves.every(isName), id);
      assert.deepEqual(outcome.moves, MOVED_ENTRIES.filter((name) => outcome.moves.includes(name)), `moves in order ${id}`);
      row.moves = outcome.moves;
    } else {
      assert.ok(DEFERRALS.includes(outcome.deferred.reason), id);
      row.deferred = outcome.deferred;
    }
    return row;
  });
  assert.equal(new Set(planStart.map((r) => r.id)).size, planStart.length, 'plan_start ids once');

  return {
    meta,
    source: 'design 0013 (5.4b: What moves, The move; the amendment of 2026-11-21): every case and outcome is the design\'s, written by hand in vectors/generator/layout.js; no reference implementation exists.',
    formats: FORMATS,
    constants: CONSTANTS,
    moved_entries: MOVED_ENTRIES,
    journals,
    written,
    rollback,
    roll_forward: rollForward,
    placeholder,
    plan_start: planStart,
  };
}

module.exports = { buildLayout };
