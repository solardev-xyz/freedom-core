'use strict';

// rad.read's composed ops and main's re-serialized ones (design 0008,
// "Methods", "JSON results" and "Tests first"): main's own code at the
// reference composes every answer here. A scripted add-on stands in for
// libradicle.node: each case lists the JSON texts its exports return, in
// libradicle's shapes (src/json.rs at the service's pin), and the reference's
// real radicle-embedded.js, radicle-api-protocol.js and radicle-manager.js
// run on them, through naming.js's harness: their own requires are stubbed,
// and no reference code is copied. A case marked `synthetic` holds a text
// libradicle never writes (whitespace, a repeated key, a float, an escape
// serde_json doesn't make): it pins how main's JSON.parse and JSON.stringify
// treat it.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const { isDeepStrictEqual } = require('node:util');
const { loadWithInternals } = require('./naming');

// Where the reference looks for the add-on: FREEDOM_RADICLE_ADDON, which
// the stubbed `fs` says exists and the harness answers with the script.
const ADDON = '/freedom-core-vectors/libradicle.node';

const RID = 'rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5';
const RID2 = 'rad:z2M1tqMip5a9U8HJBZG5vnuSL24dC';
const RID3 = 'rad:z4V1sjrXqjvFdnCUbxPFqd5p4DtH5';
const REV = 'a'.repeat(40);
const OID = (n) => n.toString(16).padStart(2, '0').repeat(20);
const DID = 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw';
const DID2 = 'did:key:z6MkfG5kHWh9VjcuGfC2rHwRfgnL6P3z1ijj9KzxrmwtGzLQ';
const NID = DID.slice('did:key:'.length);
const NID2 = DID2.slice('did:key:'.length);
const BS = String.fromCharCode(92);
/** A JSON `\uXXXX` escape, built here so no source escape is decoded. */
const U = (hex) => `${BS}u${hex}`;
const ch = (code) => String.fromCodePoint(code);

const text = (value) => JSON.stringify(value);
const error = (message) => text({ error: message });

// libradicle's shapes, key for key (src/json.rs): its `json!` objects keep
// their keys' order, as heartwood's radicle crate turns on serde_json's
// `preserve_order`; `object!` and serde's derives write theirs.
const repoInfo = (over = {}) => text({
  rid: RID,
  name: 'reads',
  description: 'A fixture.',
  defaultBranch: 'master',
  head: OID(1),
  delegates: [DID],
  threshold: 1,
  visibility: { type: 'public' },
  issuesOpen: 1,
  patchesOpen: 0,
  ...over,
});
const seeding = (n) => text({ seeding: n });
const entry = (name, kind, dir = '') => ({ name, path: dir ? `${dir}/${name}` : name, kind });
const signature = { name: 'Fixture', email: 'fixture@example.invalid', time: 1700000000 };
const treeAt = (entries) => text({
  entries,
  lastCommit: { id: REV, summary: 'First', description: '', author: signature, committer: signature },
});
const blob = (name, content) => (content === null
  ? text({ binary: true, name })
  : text({ binary: false, name, content }));
const author = (did = DID) => ({ id: did });
const comment = (id, body, timestamp, replyTo = null, did = DID) => ({
  id, author: author(did), body, timestamp, replyTo,
});
const issue = (n, state, over = {}) => ({
  id: OID(0x10 + n),
  author: author(),
  title: `Issue ${n}`,
  state,
  labels: [],
  assignees: [],
  discussion: [comment(OID(0x30 + n), `Body ${n}.`, 1700000000000 + n)],
  ...over,
});
const OPEN = { status: 'open' };
const SOLVED = { status: 'closed', reason: 'solved' };
const OTHER = { status: 'closed', reason: 'other' };
const review = (n) => ({ id: OID(0x50 + n), author: author(DID2), verdict: 'accept', summary: 'Looks good.', timestamp: 1700000100000 });
const revision = (n, over = {}) => ({
  id: OID(0x40 + n),
  author: author(),
  description: `Revision ${n}.`,
  base: OID(2),
  oid: OID(3),
  timestamp: 1700000050000 + n,
  discussions: [],
  reviews: [],
  ...over,
});
const patch = (n, state, over = {}) => ({
  id: OID(0x20 + n),
  author: author(),
  title: `Patch ${n}`,
  state,
  target: 'delegates',
  labels: [],
  assignees: [],
  revisions: [revision(n)],
  merges: [],
  ...over,
});
const remote = (id, did, delegate, heads) => ({ id, did, delegate, heads });
/** `heads` as libradicle's `BTreeMap` writes it: keys in byte order. */
const sortedHeads = (names) => Object.fromEntries([...names].sort((a, b) => (Buffer.from(a) < Buffer.from(b) ? -1 : 1)).map((name, i) => [name, OID(0x60 + i)]));
/** An object text with its members in exactly this order, as a writer that
 * keeps order emits it (a JS object literal would move index keys first). */
const ordered = (members) => `{${members.map(([key, value]) => `${JSON.stringify(key)}:${value}`).join(',')}}`;
const remotesText = (remotes) => `[${remotes.map((r) => ordered([
  ['id', JSON.stringify(r.id)], ['did', JSON.stringify(r.did)], ['delegate', JSON.stringify(r.delegate)],
  ['heads', ordered(Object.keys(r.heads).sort((a, b) => (Buffer.from(a) < Buffer.from(b) ? -1 : 1)).map((k) => [k, JSON.stringify(r.heads[k])]))],
])).join(',')}]`;

const ISSUES = [
  issue(1, OPEN),
  issue(2, SOLVED),
  issue(3, OPEN, { labels: ['bug', 'good first issue'], assignees: [DID2] }),
  issue(4, OTHER),
  issue(5, OPEN, {
    title: `Quotes " and ${ch(0x5c)} and ${ch(0)}${ch(0x1f)}${ch(0x7f)} and caf${ch(0xe9)} ${ch(0x1f600)} ${ch(0x2028)}`,
    discussion: [
      comment(OID(0x35), 'First.', 1700000000005),
      comment(OID(0x36), 'A reply.', 1700000000006, OID(0x35), DID2),
    ],
  }),
];
const PATCHES = [
  patch(1, { status: 'draft' }),
  patch(2, OPEN, { revisions: [revision(2, { discussions: [comment(OID(0x37), 'On the revision.', 1700000000007)], reviews: [review(2)] })] }),
  patch(3, { status: 'archived' }),
  patch(4, { status: 'merged', revision: OID(0x44), commit: OID(5) }, {
    merges: [{ author: author(), revision: OID(0x44), commit: OID(5), timestamp: 1700000200000 }],
  }),
  patch(5, { status: 'open', conflicts: [[OID(0x45), OID(6)]] }),
];

// What main's JSON.parse and JSON.stringify make of a text: numbers,
// strings, objects and their keys, whitespace. Each is served through
// `remotes`, which main parses and writes again whatever its shape.
const RESTRINGIFY = [
  { id: 'integers', text: '[0,-1,9007199254740991,9007199254740992,9007199254740993,18446744073709551615,-9223372036854775808,123456789012345678901,100000000000000000000,1000000000000000000000]' },
  { id: 'negative-zero', text: '[-0,-0.0,0.0,0e5,-0e-5]', synthetic: true },
  { id: 'floats', text: '[1.5,0.1,0.30000000000000004,1.0,100e-2,1E5,1e20,1e21,1e-6,1e-7,0.000001,1.2e-7,5e-324,1.7976931348623157e308,1e400,-1e400,2.5e-8,123456789.123456789,-0.000123]', synthetic: true },
  { id: 'whitespace', text: ' \t\n\r[ 1 ,\t{ "a" : [ ] , "b" :{ } } ,"x" ]\n', synthetic: true },
  { id: 'escapes', text: `["${U('0000')}${U('001f')}${U('001F')}${U('0008')}${U('000c')}${BS}b${BS}f${BS}n${BS}r${BS}t${BS}"${BS}${BS}${BS}/${U('007f')}${U('00e9')}${U('2028')}${U('2029')}${U('d83d')}${U('de00')}","${U('d800')}","x${U('dc00')}y","${U('dbff')}${U('dbff')}${U('dfff')}","${U('0022')}${U('005c')}${U('002f')}"]`, synthetic: true },
  { id: 'raw-text', text: JSON.stringify([`caf${ch(0xe9)} ${ch(0x1f600)} ${ch(0x2028)}${ch(0x2029)} ${ch(0x7f)} ${ch(0xfeff)}`, `${ch(0)}${ch(1)}${ch(0x1f)} "${ch(0x5c)}`, '']) },
  { id: 'index-keys', text: ordered([['b', '1'], ['2', '2'], ['a', '3'], ['10', '4'], ['0', '5'], ['01', '6'], ['-1', '7'], ['1.5', '8'], [' 1', '9'], ['4294967294', '10'], ['4294967295', '11'], ['9007199254740991', '12'], ['1e3', '13'], ['', '14']]), synthetic: true },
  { id: 'repeated-keys', text: ordered([['a', '1'], ['b', '2'], ['a', '3'], ['3', '4'], ['c', ordered([['x', '1'], ['x', '2']])], ['3', '5'], [`${ch(0x61)}`, '6']]), synthetic: true },
  { id: 'escaped-keys', text: `{"${U('0061')}":1,"a":2,"${U('0031')}":3,"${U('d800')}":4,"${BS}"":5,"${BS}${BS}":6,"${U('d83d')}${U('de00')}":7,"${ch(0x1f600)}":8}`, synthetic: true },
  { id: 'proto-key', text: '{"__proto__":{"a":1},"constructor":2,"toString":3}', synthetic: true },
  { id: 'nested', text: `[{"z":[{"2":"two","1":"one"}],"y":{"b":{"0":null,"a":true}}},[],{},[[[]]],false,null,true,"",{"":""}]` },
  { id: 'deep', text: '['.repeat(100) + '{"1":1,"0":0}' + ']'.repeat(100), synthetic: true },
  { id: 'number-root', text: '42' },
  { id: 'string-root', text: `"${U('00e9')}"`, synthetic: true },
];

// Query strings for the COB pages, through URLSearchParams as main reads
// them: JavaScript's parseInt, its whitespace, and the clamps.
const PAGE_QUERIES = [
  '', 'status=open', 'status=closed', 'status=', 'status=solved', 'status=open+', 'status=OPEN', 'status=open&status=closed',
  'perPage=2', 'perPage=2&page=1', 'page=2&perPage=2', 'page=3&perPage=2', 'page=1',
  'status=open&perPage=1&page=1', 'status=closed&perPage=1&page=1',
  'perPage=0', 'perPage=-5', 'perPage=101', 'perPage=100', 'perPage=1', 'perPage=2.9', 'perPage=%202', 'perPage=%C2%A02',
  'perPage=%E2%80%A82', 'perPage=%C2%852', 'perPage=%EF%BB%BF2', 'perPage=%E1%A0%8E2', 'perPage=%2B2', 'perPage=2abc',
  'perPage=abc', 'perPage=0x2', 'perPage=1e1', 'perPage=', 'perPage=%2B0', 'perPage=-0', 'perPage=1&perPage=5',
  'perPage=%0B%0C%092', 'perPage=%E3%80%802', 'perPage=--2', 'perPage=+-2', 'perPage=%E2%80%8B2',
  'page=-1&perPage=2', 'page=-0&perPage=2', 'page=1.9&perPage=2', 'page=99999999999999999999&perPage=1',
  `page=${'9'.repeat(400)}&perPage=1`, 'page=Infinity&perPage=2', 'page=%091&perPage=2', 'page=%0A1&perPage=2',
  'page=%E1%A0%8E1&perPage=2', 'page=2&perPage=-3', 'page=4&perPage=1', 'page=5&perPage=1', 'page=0&perPage=5',
];

function cases() {
  const out = [];
  const add = (c) => out.push(c);
  const rid = { rid: RID };

  // readme_at: the README candidates in main's order, from the root tree's
  // blobs, then that blob's text with "path" spliced in.
  const readme = (id, entries, blobs, extra = {}) => add({
    id: `readme-${id}`, op: 'readme_at', args: { rid: RID, revision: REV }, ...extra,
    addon: [
      { export: 'treeAt', args: [RID, REV, ''], text: Array.isArray(entries) ? treeAt(entries) : entries },
      ...blobs.map(([name, t]) => ({ export: 'blobAt', args: [RID, REV, name], text: t })),
    ],
  });
  readme('md', [entry('docs', 'tree'), entry('README.md', 'blob'), entry('src', 'tree')], [['README.md', blob('README.md', '# Reads\n')]]);
  readme('priority', [entry('README', 'blob'), entry('README.txt', 'blob'), entry('readme.md', 'blob')], [['README.txt', blob('README.txt', 'Plain.\n')]]);
  readme('markdown', [entry('README.markdown', 'blob'), entry('README.txt', 'blob')], [['README.markdown', blob('README.markdown', 'Markdown.\n')]]);
  readme('lowercase', [entry('readme.md', 'blob'), entry('Readme.md', 'blob')], [['readme.md', blob('readme.md', 'lower\n')]]);
  readme('bare', [entry('README.md', 'tree'), entry('README', 'blob')], [['README', blob('README', 'Bare.\n')]]);
  readme('submodule', [entry('README.md', 'submodule'), entry('README.MD', 'blob'), entry('Readme', 'blob')], []);
  readme('none', [entry('src', 'tree'), entry('readme.txt', 'blob')], []);
  readme('empty-tree', [], []);
  readme('binary', [entry('README.md', 'blob')], [['README.md', blob('README.md', null)]]);
  readme('escapes', [entry('README.md', 'blob')], [['README.md', blob('README.md',
    `"quoted" ${ch(0x5c)} back\tslash\n${ch(0)}${ch(0x1f)}${ch(0x7f)} caf${ch(0xe9)} ${ch(0x1f600)} ${ch(0x2028)} ends with }`)]]);
  readme('lossy', [entry('README.md', 'blob')], [['README.md', blob('README.md', `caf${ch(0xfffd)} cr${ch(0xfffd)}me\n`)]]);
  readme('empty-blob', [entry('README.md', 'blob')], [['README.md', blob('README.md', '')]]);
  readme('tree-not-found', error(`revision ${REV} not found`), []);
  readme('tree-failed', error('the tree is nested deeper than 64 levels'), []);
  readme('blob-failed', [entry('README.md', 'blob')], [['README.md', error('16777217 bytes is over the limit of 16777216')]]);
  readme('blob-not-found', [entry('README.md', 'blob')], [['README.md', error('blob README.md does not exist')]]);

  // repo_meta: buildRepoMeta of repoInfo and seeders.
  const meta = (id, info, seeders, extra = {}) => add({
    id: `repo-meta-${id}`, op: 'repo_meta', args: rid, ...extra,
    addon: [
      { export: 'repoInfo', args: [RID], text: info },
      ...(seeders === undefined ? [] : [{ export: 'seeders', args: [RID], text: seeders }]),
    ],
  });
  meta('public', repoInfo(), seeding(3));
  meta('private', repoInfo({ visibility: { type: 'private', allow: [DID2, DID] }, delegates: [DID, DID2], threshold: 2 }), seeding(0));
  meta('seeders-failed', repoInfo({ issuesOpen: 4, patchesOpen: 2 }), error(`node thread: seeds for ${RID} unavailable`));
  meta('escapes', repoInfo({ name: `caf${ch(0xe9)} "x" ${ch(0x1f600)}`, description: `back${ch(0x5c)}slash\n${ch(0)}${ch(0x2028)}`, defaultBranch: 'main' }), seeding(12));
  meta('not-found', error(`repository ${RID} not found`));
  meta('failed', error(`${RID} has no canonical identity head to size its identity document from`));
  meta('fallbacks', text({ rid: RID, delegates: null, threshold: null, visibility: null, issuesOpen: 0 }), seeding(1), { synthetic: true });
  meta('falsy', text({ rid: RID, name: '', delegates: 0, threshold: 0, visibility: '', head: null, patchesOpen: false }), seeding(1), { synthetic: true });
  meta('seeders-without-seeding', repoInfo(), text({ seeders: 2 }), { synthetic: true });
  meta('seeders-null', repoInfo(), 'null', { synthetic: true });
  meta('seeders-number', repoInfo(), '7', { synthetic: true });
  meta('big-numbers', repoInfo({ issuesOpen: 9007199254740993, threshold: 18446744073709551615 }), seeding(9007199254740993));
  meta('unordered-info', ordered([['visibility', ordered([['type', '"private"'], ['allow', `["${DID2}"]`], ['1', '0']])], ['rid', `"${RID}"`], ['name', '"x"'], ['name', '"y"']]), seeding(1), { synthetic: true });

  // repos_meta: one repo_meta per listRepos entry, in its order.
  const listed = (...rids) => text(rids.map((r, i) => ({ rid: r, name: `repo ${i}`, description: '' })));
  const reposMeta = (id, list, per, extra = {}) => add({
    id: `repos-meta-${id}`, op: 'repos_meta', args: {}, ...extra,
    addon: [
      { export: 'listRepos', args: [], text: list },
      ...per.flatMap(([r, info, seeders]) => [
        { export: 'repoInfo', args: [r], text: info },
        ...(seeders === undefined ? [] : [{ export: 'seeders', args: [r], text: seeders }]),
      ]),
    ],
  });
  reposMeta('empty', '[]', []);
  reposMeta('three', listed(RID2, RID, RID3), [
    [RID2, repoInfo({ rid: RID2, name: 'second' }), seeding(2)],
    [RID, repoInfo(), seeding(3)],
    [RID3, repoInfo({ rid: RID3, name: 'third', visibility: { type: 'private', allow: [DID] } }), error('node thread: unavailable')],
  ]);
  reposMeta('info-failed', listed(RID, RID2, RID3), [
    [RID, repoInfo(), seeding(1)],
    [RID2, error(`repository ${RID2} not found`)],
    [RID3, repoInfo({ rid: RID3 }), seeding(1)],
  ]);
  reposMeta('two-failed', listed(RID, RID2, RID3), [
    [RID, error('first failure')],
    [RID2, repoInfo({ rid: RID2 }), seeding(1)],
    [RID3, error('third failure')],
  ]);
  reposMeta('list-failed', error('16777217 bytes is over the limit of 16777216'), []);

  // The COB pages: filtered by state.status, then paged.
  const ISSUES_TEXT = text(ISSUES);
  for (const query of PAGE_QUERIES) {
    add({ id: `issues-page-${query || 'none'}`, op: 'issues_page', query, addon: [{ export: 'issues', args: [RID], text: ISSUES_TEXT }] });
  }
  const PATCHES_TEXT = text(PATCHES);
  for (const query of ['', 'status=draft', 'status=open', 'status=archived', 'status=merged', 'status=open&perPage=1&page=1', 'perPage=2&page=2']) {
    add({ id: `patches-page-${query || 'none'}`, op: 'patches_page', query, addon: [{ export: 'patches', args: [RID], text: PATCHES_TEXT }] });
  }
  add({ id: 'issues-page-empty', op: 'issues_page', query: 'status=open', addon: [{ export: 'issues', args: [RID], text: '[]' }] });
  // More than a page of 100: the clamp, and the pages past it.
  const MANY = text(Array.from({ length: 120 }, (_, n) => ({ state: n % 3 ? OPEN : SOLVED, n })));
  for (const query of ['perPage=101', 'perPage=100&page=1', 'status=open&perPage=100', '', 'page=3']) {
    add({ id: `issues-page-many-${query || 'none'}`, op: 'issues_page', query, synthetic: true, addon: [{ export: 'issues', args: [RID], text: MANY }] });
  }
  add({
    id: 'issues-page-odd-items', op: 'issues_page', query: 'status=1', synthetic: true,
    addon: [{ export: 'issues', args: [RID], text: text([null, 1, 'open', [], {}, { state: null }, { state: { status: 1 } }, { state: { status: '1' }, n: 1 }, { state: ['1'] }, { state: 'x', status: '1' }]) }],
  });
  add({
    id: 'issues-page-repeated-state', op: 'issues_page', query: 'status=open', synthetic: true,
    addon: [{ export: 'issues', args: [RID], text: `[${ordered([['state', '{"status":"closed"}'], ['n', '1'], ['state', `{"status":"closed","status":"open"}`]])},${ordered([['state', '{"status":"open"}'], ['state', '{"status":"closed"}']])},{"${U('0073')}tate":{"st${U('0061')}tus":"op${U('0065')}n"}}]` }],
  });
  add({
    id: 'issues-page-big-numbers', op: 'issues_page', query: '',
    addon: [{ export: 'issues', args: [RID], text: text([issue(6, OPEN, { discussion: [comment(OID(0x38), 'Late.', 18446744073709551615)] })]).replace('18446744073709552000', '18446744073709551615') }],
  });
  add({ id: 'issues-page-not-found', op: 'issues_page', query: '', addon: [{ export: 'issues', args: [RID], text: error(`repository ${RID} not found`) }] });
  add({ id: 'patches-page-failed', op: 'patches_page', query: 'status=open', addon: [{ export: 'patches', args: [RID], text: error('cached COB id "x": invalid') }] });

  // The ops main parses and writes again.
  for (const [n, i] of ISSUES.entries()) {
    add({ id: `issue-${n + 1}`, op: 'issue', args: { rid: RID, issue_id: i.id }, addon: [{ export: 'issue', args: [RID, i.id], text: text(i) }] });
  }
  add({ id: 'issue-short-id', op: 'issue', args: { rid: RID, issue_id: ISSUES[0].id.slice(0, 7) }, addon: [{ export: 'issue', args: [RID, ISSUES[0].id.slice(0, 7)], text: text(ISSUES[0]) }] });
  add({
    id: 'issue-big-timestamp', op: 'issue', args: { rid: RID, issue_id: OID(0x17) },
    addon: [{ export: 'issue', args: [RID, OID(0x17)], text: text(issue(7, OPEN, { id: OID(0x17), discussion: [comment(OID(0x39), 'x', 1)] })).replace('"timestamp":1', '"timestamp":9007199254740993') }],
  });
  add({ id: 'issue-not-found', op: 'issue', args: { rid: RID, issue_id: OID(0x19) }, addon: [{ export: 'issue', args: [RID, OID(0x19)], text: error(`node thread: issue ${OID(0x19)} not found`) }] });
  add({ id: 'issue-failed', op: 'issue', args: { rid: RID, issue_id: OID(0x19) }, addon: [{ export: 'issue', args: [RID, OID(0x19)], text: error('33554433 bytes is over the limit of 16777216') }] });
  for (const [n, p] of PATCHES.entries()) {
    add({ id: `patch-${n + 1}`, op: 'patch', args: { rid: RID, patch_id: p.id }, addon: [{ export: 'patch', args: [RID, p.id], text: text(p) }] });
  }
  add({ id: 'patch-not-found', op: 'patch', args: { rid: RID, patch_id: OID(0x29) }, addon: [{ export: 'patch', args: [RID, OID(0x29)], text: error(`node thread: patch ${OID(0x29)} not found`) }] });
  const remotes = (id, t, extra = {}) => add({ id: `remotes-${id}`, op: 'remotes', args: rid, ...extra, addon: [{ export: 'remotes', args: [RID], text: t }] });
  remotes('two', remotesText([
    remote(NID, DID, true, sortedHeads(['master', 'feature/x'])),
    remote(NID2, DID2, false, sortedHeads(['master'])),
  ]));
  remotes('index-branches', remotesText([
    remote(NID, DID, true, sortedHeads(['10', '2', 'main', '0', '01', '4294967294', '4294967295', '-1', '1.5', 'feature/9', '9007199254740993'])),
  ]));
  remotes('empty', '[]');
  remotes('no-heads', remotesText([remote(NID, DID, true, {})]));
  remotes('not-found', error(`repository ${RID} not found`));
  for (const r of RESTRINGIFY) remotes(r.id, r.text, r.synthetic ? { synthetic: true } : {});
  const stats = (id, t) => add({ id: `repo-stats-${id}`, op: 'repo_stats', args: { rid: RID, revision: REV }, addon: [{ export: 'repoStats', args: [RID, REV], text: t }] });
  stats('counts', text({ commits: 17, branches: 2, contributors: 3 }));
  stats('zero', text({ commits: 0, branches: 0, contributors: 0 }));
  stats('failed', error('8388609 bytes is over the limit of 8388608'));
  stats('not-found', error(`revision ${REV} not found`));

  // node_info: status, and listRepos for the count.
  const node = (id, status, list) => add({
    id: `node-info-${id}`, op: 'node_info', args: {},
    addon: [{ export: 'status', args: [], text: status }, ...(list === undefined ? [] : [{ export: 'listRepos', args: [], text: list }])],
  });
  node('three', text({ connectedPeers: 3 }), listed(RID, RID2, RID3));
  node('none', text({ connectedPeers: 0 }), '[]');
  node('listing-failed', text({ connectedPeers: 2 }), error('16777217 bytes is over the limit of 16777216'));
  // A failed status fails the call: the listing is never read.
  node('status-failed', error('node thread: the node is not running'));
  return out;
}

function loadMain(checkout) {
  const world = { script: [], calls: [], warnings: [], unscripted: [] };
  const answer = (name, args) => {
    world.calls.push({ export: name, args });
    const found = world.script.find((e) => e.export === name && isDeepStrictEqual(e.args, args));
    if (!found) {
      world.unscripted.push({ export: name, args });
      return error(`unscripted ${name}`);
    }
    found.used = true;
    return found.text;
  };
  // Every export the reference asks for is a function of the script.
  const addon = new Proxy({}, { get: (_, name) => (typeof name === 'string' ? (...args) => answer(name, args) : undefined) });
  const log = {
    info() {}, debug() {}, error() {}, log() {},
    warn: (...parts) => world.warnings.push(parts.map((p) => String(p)).join(' ')),
  };
  const embedded = loadWithInternals(checkout, 'src/main/radicle-embedded.js', [], {
    './logger': log,
    fs: { ...fs, existsSync: (p) => p === ADDON || fs.existsSync(p) },
    [ADDON]: addon,
  });
  const protocol = loadWithInternals(checkout, 'src/main/radicle-api-protocol.js', ['serveRepoApi', 'serveNodeApi', 'handleRadicleApiRequest'], {
    './logger': log,
    './radicle-embedded': embedded,
    './radicle-manager': { isDisabledForProfile: () => false },
    './webrequest-dispatcher': { registerWebRequestHandler() {} },
    './private/private-log-context': { runWithPrivateLogContext: (_, fn) => fn(), redactForLog: (value) => value },
  });
  const manager = loadWithInternals(checkout, 'src/main/radicle-manager.js', [], {
    electron: { ipcMain: { handle() {}, on() {}, removeHandler() {} }, BrowserWindow: { getAllWindows: () => [] } },
    './logger': log,
    './radicle-embedded': embedded,
    './profile-paths': { getRadicleDataDir: () => '/nonexistent', prepareRadicleDataDir: () => '/nonexistent' },
    './profile-resolver': { getActiveProfile: () => null },
    './radicle/seed-status': {},
    './service-registry': { MODE: {}, updateService() {}, setStatusMessage() {}, clearService() {} },
  }, 'module.exports.__setRunning = () => { currentState = STATUS.RUNNING; };');
  return { world, protocol: protocol.__internals, handle: protocol.__internals.handleRadicleApiRequest, manager };
}

const answered = async (response) => ({ status: response.status, body: await response.text() });

/** The service's `node_info` (the design's: 0008, "Methods"), from the
 * scripted status and listing, as main's two callers then read it. */
function nodeInfo(c) {
  const status = JSON.parse(c.addon.find((e) => e.export === 'status').text);
  if (status.error) return { source: 'design', error: { message: status.error } };
  const list = JSON.parse(c.addon.find((e) => e.export === 'listRepos').text);
  const failed = !Array.isArray(list) && list.error;
  return {
    source: 'design',
    body: JSON.stringify({
      connected_peers: status.connectedPeers,
      repos_total: failed ? null : list.length,
      repos_error: failed ? list.error : null,
    }),
  };
}

/** Main's answers rebuilt from `node_info` as 0008 says main reads it:
 * they must be the reference's own, or the design's op can't serve them. */
function checkNodeInfo(c, version) {
  const { expect, main } = c;
  const fail = (message) => ({ status: 503, body: JSON.stringify({ error: message }) });
  if (expect.error) {
    assert.deepEqual(main.root, fail(expect.error.message), c.id);
    assert.deepEqual(main.stats, fail(expect.error.message), c.id);
    assert.deepEqual(main.connections, { success: false, error: { code: 'GET_CONNECTIONS_FAILED', message: expect.error.message }, count: 0, reposCount: null, version }, c.id);
    return;
  }
  const info = JSON.parse(expect.body);
  assert.deepEqual(main.root, { status: 200, body: JSON.stringify({ version: 'embedded', mode: 'embedded' }) }, c.id);
  assert.deepEqual(main.stats, info.repos_error === null
    ? { status: 200, body: JSON.stringify({ repos: { total: info.repos_total }, peers: { connected: info.connected_peers } }) }
    : fail(info.repos_error), c.id);
  assert.deepEqual(main.connections, { success: true, count: info.connected_peers, reposCount: info.repos_total, version }, c.id);
}

async function run(main, c) {
  const { world, protocol, handle, manager } = main;
  world.script = c.addon.map((e) => ({ ...e }));
  world.calls = [];
  world.warnings = [];
  world.unscripted = [];
  const repo = (apiPath, search = '') => protocol.serveRepoApi(RID, apiPath, { search, allowPrivate: true }).then(answered);
  let result;
  switch (c.op) {
    case 'readme_at': result = await repo(`/readme/${c.args.revision}`); break;
    case 'repo_meta': result = await repo(''); break;
    case 'repos_meta': result = await handle({ url: 'radapi://local/api/v1/repos', method: 'GET', referrer: '' }).then(answered); break;
    case 'issues_page': result = await repo('/issues', c.query); break;
    case 'patches_page': result = await repo('/patches', c.query); break;
    case 'issue': result = await repo(`/issues/${c.args.issue_id}`); break;
    case 'patch': result = await repo(`/patches/${c.args.patch_id}`); break;
    case 'remotes': result = await repo('/remotes'); break;
    case 'repo_stats': result = await repo(`/stats/tree/${c.args.revision}`); break;
    case 'node_info': {
      const root = await protocol.serveNodeApi('/').then(answered);
      const stats = await protocol.serveNodeApi('/api/v1/stats').then(answered);
      manager.__setRunning();
      const connections = await manager.getConnections();
      result = { root, stats, connections };
      break;
    }
    default: throw new Error(`no op ${c.op}`);
  }
  assert.deepEqual(world.unscripted, [], `${c.id}: unscripted add-on calls`);
  for (const e of world.script) assert.ok(e.used, `${c.id}: scripted ${e.export}(${JSON.stringify(e.args)}) never read`);
  return { ...result, calls: world.calls, warnings: world.warnings };
}

async function buildRadicleReads(checkout, meta) {
  const previous = process.env.FREEDOM_RADICLE_ADDON;
  process.env.FREEDOM_RADICLE_ADDON = ADDON;
  try {
    const main = loadMain(checkout);
    const version = main.manager.getConnections ? require(`${checkout}/src/shared/radicle-addon-version.js`).RADICLE_ADDON_VERSION : null;
    const ids = new Set();
    const built = [];
    for (const c of cases()) {
      assert.ok(!ids.has(c.id), c.id);
      ids.add(c.id);
      if (c.query !== undefined) {
        // The service's args: what main's `paginate` reads from the query.
        const params = new URLSearchParams(c.query);
        c.args = { rid: RID, status: params.get('status'), page: params.get('page'), per_page: params.get('perPage') };
      }
      const main_ = await run(main, c);
      const entry = { id: c.id, op: c.op, args: c.args };
      if (c.query !== undefined) entry.query = c.query;
      if (c.synthetic) entry.synthetic = true;
      entry.addon = c.addon;
      entry.main = main_;
      if (c.op === 'node_info') {
        entry.expect = nodeInfo(c);
        checkNodeInfo(entry, version);
      }
      built.push(entry);
    }
    // Coverage the Rust side relies on: each op answers, and fails.
    for (const op of ['readme_at', 'repo_meta', 'repos_meta', 'issues_page', 'patches_page', 'issue', 'patch', 'remotes', 'repo_stats']) {
      assert.ok(built.some((c) => c.op === op && c.main.status === 200), `${op} answers`);
      assert.ok(built.some((c) => c.op === op && c.main.status !== 200), `${op} fails`);
    }
    return {
      meta,
      formats: {
        case: '`op` and `args` are rad.read\'s, as the service takes them (design 0008, "Methods"); `query` is the page\'s query string, from which `args` are what main\'s `paginate` reads (`URLSearchParams.get` of status, page and perPage, or null).',
        addon: 'The scripted add-on: each export main calls, its arguments, and the JSON text it returns. An `{"error": …}` text is the add-on\'s failure, which main throws as an Error with that message. Every entry is read; nothing else is.',
        main: 'What the reference answers: the radapi handler\'s `status` and `body` text (serveRepoApi with allowPrivate, or the `/api/v1/repos` listing), the add-on calls in the order main made them, and what it logged (`warnings`). For node_info: `root` and `stats` (serveNodeApi\'s `/` and `/api/v1/stats`) and `connections` (the manager\'s getConnections, its node running).',
        expect: 'node_info only, the design\'s (`source: design`): the op\'s JSON body, or its error\'s message. Main\'s three answers rebuild from it; the generator checks they are the reference\'s.',
        synthetic: 'A text libradicle never writes (whitespace, a repeated key, a float, an escape serde_json doesn\'t make, a shape no serializer has): it pins main\'s JSON.parse and JSON.stringify.',
      },
      constants: { rid: RID, revision: REV },
      cases: built,
    };
  } finally {
    if (previous === undefined) delete process.env.FREEDOM_RADICLE_ADDON;
    else process.env.FREEDOM_RADICLE_ADDON = previous;
  }
}

module.exports = { buildRadicleReads };
