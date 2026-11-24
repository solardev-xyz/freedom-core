'use strict';

// vectors/swarm-grammar.json (design 0015, SWM-1): the grammar's forms and
// rows (swarm-grammar.js), and each row's honest calls, which main must
// admit, and forbidden alternatives, which main must refuse, as scenarios a
// scripted core plays against main's executor (SWM-5) and the core's
// machines are held to (SWM-3).
//
// A scenario is a parent (its row, params as main knows them, the page's
// key), its ready check, and calls in order, each with the reply main
// returned; a forbidden one ends in the call main refuses, with the rule it
// breaks. The honest calls are the core's: the reference's requests as the
// core keeps them (the named deviations' requests replaced as the design
// says: one /stamps, feed_head for an index, no read-back of a /bytes
// root, readData's verified walk), and the walks and trees the design names.

const fs = require('node:fs');
const path = require('node:path');
const { FORMS, ROWS, VALUES, DEVIATION_REQUESTS, MAIN_HEADERS, formOf, feedAddress, feedIdentifierHex } = require('./swarm-grammar');
const { withReference, content, dataOf, requestRecord } = require('./swarm-run');
const { splitTree, sha256 } = require('./swarm-node');
const C = require('./swarm-cases');

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const MiB = 1024 * 1024;
const B = 5 * MiB;

/** A call as the scenarios write it. */
function call(form, method, p, { query = [], headers = [], body = null, maxBytes, feed, tree, reply } = {}) {
  const out = { form, method, path: p };
  if (query.length) out.query = query;
  out.headers = headers;
  if (body) out.body = body.length <= 8192 ? { bytes: body.length, base64: b64(body) } : { bytes: body.length, sha256: sha256(body) };
  if (maxBytes !== undefined) out.max_bytes = maxBytes;
  if (feed) out.feed = feed;
  if (tree) out.tree = tree;
  if (reply) out.reply = reply;
  return out;
}

const mainHeaders = (extra = []) => [['accept', MAIN_HEADERS.accept], ['accept-encoding', MAIN_HEADERS['accept-encoding']], ...extra];

/** A recorded request turned into the core's call (headers as main sends them). */
function coreCall(r, form) {
  const own = r.headers.filter(([n]) => n !== 'accept' && n !== 'accept-encoding');
  const out = { form, method: r.method, path: r.path };
  if (r.query?.length) out.query = r.query;
  out.headers = mainHeaders(own);
  if (r.body) out.body = r.body;
  if (r.feed) out.feed = r.feed;
  if (r.max_bytes !== undefined) out.max_bytes = r.max_bytes;
  out.reply = { status: r.status };
  return out;
}

function honestFromMethods(env, methods, nodeBodies) {
  const out = [];
  for (const c of methods) {
    c.steps.forEach((step, k) => {
      const calls = [];
      let ready = null;
      let walkable = true;
      step.requests.forEach((r, j) => {
        if (r.ready) {
          ready = r.ready;
          return;
        }
        if (r.form) {
          const coreForm = coreCall(r, r.form);
          const body = nodeBodies.get(`${c.id}/${k}/${j}`);
          if (body && (r.form === 'chunk') && body.length <= 4201) coreForm.reply.body = { base64: b64(body) };
          calls.push(coreForm);
          return;
        }
        if (r.deviation === 'stamps-one-read' || r.deviation === 'feed-wrap-root') return;
        if (r.deviation === 'index-probe') {
          const headers = nodeBodies.get(`${c.id}/${k}/${j}/headers`) || {};
          const reply = { status: r.status };
          if (r.status >= 200 && r.status < 300) {
            reply.headers = Object.fromEntries(Object.entries(headers).filter(([n]) => n.startsWith('swarm-feed-index')));
          }
          calls.push(call('feed_head', 'GET', r.path, { headers: mainHeaders([['swarm-only-root-chunk', 'true']]), reply }));
          return;
        }
        if (r.deviation === 'read-data-verified') {
          const walk = env.walks.get(r.path.slice('/bytes/'.length));
          if (!walk) {
            walkable = false;
            return;
          }
          calls.push(...walk);
          return;
        }
        walkable = false;
      });
      if (!walkable || (calls.length === 0 && !ready)) return;
      out.push({
        id: `${c.id}${c.steps.length > 1 ? `/${k}` : ''}`,
        row: rowOf(step),
        from: `methods/${c.id}`,
        key: c.origin,
        params: step.params,
        ...(ready ? { ready: { check: ready, ok: true } } : {}),
        ...(rowOf(step) && ROWS[rowOf(step)]?.ready === 'publish' ? { ready: { check: 'publish', ok: true } } : {}),
        calls,
      });
    });
  }
  return out;
}

function rowOf(step) {
  if (typeof step.method !== 'string') return null;
  const name = step.method.replace(/^swarm_/, '');
  if (name !== 'readFeedEntry') return name;
  const params = Object.fromEntries((step.params.object || []).map(([k, v]) => [k, v]));
  const index = params.index;
  return index && !index.undefined && !index.null ? 'readFeedEntry_index' : 'readFeedEntry_latest';
}

/** readData's verified walk over a tree whose chunks are known: the root, every data intermediate, the ranged leaf stream. */
function walkOf(root, size, intermediates) {
  const calls = [];
  for (const node of intermediates) calls.push(call('chunk', 'GET', `/chunks/${node.address}`, { headers: mainHeaders(), tree: { length: node.length, depth: node.depth },
    reply: { status: 200, ...(node.wire ? { body: { base64: b64(node.wire) } } : { body_ref: node.ref }) } }));
  calls.push(call('bytes', 'GET', `/bytes/${root}`, { headers: mainHeaders([['range', `bytes=0-${size - 1}`]]), maxBytes: size, reply: { status: 206 } }));
  return calls;
}

/** The intermediates of a ChunkSplitter tree below its root, breadth first, with their depths. */
function plainIntermediates(tree) {
  const byAddress = new Map(tree.chunks.map((c) => [c.address, c]));
  const out = [];
  let level = [{ chunk: tree.root, depth: 0 }];
  while (level.length) {
    const next = [];
    for (const { chunk, depth } of level) {
      if (chunk.span <= 4096n) continue;
      for (let at = 0; at < chunk.payload.length; at += 32) {
        const child = byAddress.get(chunk.payload.subarray(at, at + 32).toString('hex'));
        if (child && child.span > 4096n) {
          out.push({ address: child.address, length: Number(child.span), depth: depth + 1, wire: child.wire });
          next.push({ chunk: child, depth: depth + 1 });
        }
      }
    }
    level = next;
  }
  return out;
}

/** The core's walk for each tree a readData case reads, by root. */
async function prepareWalks(env, methods) {
  const walks = new Map();
  for (const tree of env.trees.values()) {
    const size = Number(tree.root.span);
    if (size <= 4096 || size > B) continue;
    walks.set(tree.root.address, walkOf(tree.root.address, size, plainIntermediates(tree)));
  }
  // A root whose span carries a redundancy level, over two plain leaves.
  walks.set(env.levelRoot.address, walkOf(env.levelRoot.address, 8192, []));
  env.walks = walks;
}

/** The walks over design 0009's Bee and Ant trees (vectors/dweb-verify.json), every redundancy level. */
function dwebWalks(env, dwebVerify) {
  const out = [];
  const chunks = dwebVerify.swarm.chunks;
  for (const file of dwebVerify.swarm.files) {
    if (file.size <= 4096 || file.size > B) continue;
    const data = content(file.seed, file.size);
    const inTree = new Set(file.tree);
    // The walk: every data intermediate below the root (the tree's own
    // reads, which leave parities out), with its depth from the root.
    const depthOf = new Map([[file.root, 0]]);
    const intermediates = [];
    const queue = [file.root];
    while (queue.length) {
      const address = queue.shift();
      const wire = Buffer.from(chunks[address], 'base64');
      const payload = wire.subarray(8);
      for (let at = 0; at + 32 <= payload.length; at += 32) {
        const ref = payload.subarray(at, at + 32).toString('hex');
        if (!inTree.has(ref) || depthOf.has(ref)) continue;
        depthOf.set(ref, depthOf.get(address) + 1);
        const childWire = Buffer.from(chunks[ref], 'base64');
        const span = Buffer.from(childWire.subarray(0, 8));
        if (span[7] > 128) span[7] = 0;
        intermediates.push({ address: ref, length: Number(span.readBigUInt64LE(0)), depth: depthOf.get(ref), ref: 'dweb-verify.json swarm.chunks' });
        queue.push(ref);
      }
    }
    const rootCall = call('chunk', 'GET', `/chunks/${file.root}`, { headers: mainHeaders(), reply: { status: 200, body_ref: 'dweb-verify.json swarm.chunks' } });
    const leaf0 = Buffer.concat([u64le(Math.min(4096, file.size)), data.subarray(0, 4096)]);
    const leafAddress = env.core.makeContentAddressedChunk(data.subarray(0, 4096)).address.toHex();
    const leafDepth = Math.max(...intermediates.map((n) => n.depth), 0) + 1;
    out.push({
      id: `readData-walk-${file.id}`, row: 'readData', from: `dweb-verify.json swarm.files/${file.id}`, key: C.ORIGIN,
      params: { object: [['reference', { string: file.root }]] }, ready: { check: 'reachable', ok: true },
      calls: [rootCall, ...walkOf(file.root, file.size, intermediates),
        // The first leaf, fetched again after it failed its check in the stream.
        call('chunk', 'GET', `/chunks/${leafAddress}`, { headers: mainHeaders(), tree: { length: 4096, depth: leafDepth },
          reply: { status: 200, body: { base64: b64(leaf0) } } })],
    });
  }
  return out;
}

const u64le = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
};

/**
 * One chunk at two positions with two logical lengths: a root over [X, X],
 * X an intermediate of 128 leaves, read as 524,288 bytes and as 520,288 (its
 * last leaf then 96 bytes), so X is fetched once under each length and its
 * last leaf checked against 4,096 and 96 bytes.
 */
function twoPositions(env) {
  const { core } = env;
  const data = content('swarm-grammar/two-positions', 524288);
  const leaves = [];
  for (let i = 0; i < 128; i++) {
    const slice = data.subarray(i * 4096, (i + 1) * 4096);
    leaves.push({ address: core.makeContentAddressedChunk(slice).address.toHex(), wire: Buffer.concat([u64le(4096), slice]) });
  }
  const xPayload = Buffer.concat(leaves.map((l) => Buffer.from(l.address, 'hex')));
  const x = core.makeContentAddressedChunk(xPayload, 524288n);
  const xAddress = x.address.toHex();
  const n = 524288 + 520288;
  const rootPayload = Buffer.concat([Buffer.from(xAddress, 'hex'), Buffer.from(xAddress, 'hex')]);
  const root = core.makeContentAddressedChunk(rootPayload, BigInt(n)).address.toHex();
  const xWire = Buffer.concat([u64le(524288), xPayload]);
  const rootWire = Buffer.concat([u64le(n), rootPayload]);
  const last = leaves[127];
  const params = { object: [['reference', { string: root }]] };
  const prefix = [
    call('chunk', 'GET', `/chunks/${root}`, { headers: mainHeaders(), reply: { status: 200, body: { base64: b64(rootWire) } } }),
    call('chunk', 'GET', `/chunks/${xAddress}`, { headers: mainHeaders(), tree: { length: 524288, depth: 1 }, reply: { status: 200, body: { base64: b64(xWire) } } }),
    call('chunk', 'GET', `/chunks/${xAddress}`, { headers: mainHeaders(), tree: { length: 520288, depth: 1 }, reply: { status: 200, body: { base64: b64(xWire) } } }),
  ];
  const stream = call('bytes', 'GET', `/bytes/${root}`, { headers: mainHeaders([['range', `bytes=0-${n - 1}`]]), maxBytes: n, reply: { status: 206 } });
  const refetch = (length) => call('chunk', 'GET', `/chunks/${last.address}`, { headers: mainHeaders(), tree: { length, depth: 2 },
    reply: { status: 200, body: { base64: b64(last.wire) } } });
  const base = { row: 'readData', key: C.ORIGIN, params, ready: { check: 'reachable', ok: true },
    data: { note: 'the file is content(seed, 524288) then its first 520,288 bytes again', seed: 'swarm-grammar/two-positions', length: n } };
  return {
    honest: [{ id: 'readData-two-positions', from: 'design 0015, Values main derives (occurrences)', ...base,
      calls: [...prefix, stream, refetch(4096), refetch(96)] }],
    forbidden: [
      { id: 'readData-one-length-fetched-twice', from: 'design 0015, forbidden alternatives', ...base, rule: 'count',
        calls: [...prefix, call('chunk', 'GET', `/chunks/${xAddress}`, { headers: mainHeaders(), tree: { length: 524288, depth: 1 } })],
        note: 'one address at two lengths, fetched twice under one of them' },
      { id: 'readData-length-the-tree-does-not-give', from: 'design 0015, forbidden alternatives', ...base, rule: 'value',
        calls: [prefix[0], call('chunk', 'GET', `/chunks/${xAddress}`, { headers: mainHeaders(), tree: { length: 520289, depth: 1 } })],
        note: 'a tree.length the tree doesn\'t give that address' },
      { id: 'readData-depth-the-tree-does-not-give', from: 'design 0015, forbidden alternatives', ...base, rule: 'value',
        calls: [prefix[0], call('chunk', 'GET', `/chunks/${xAddress}`, { headers: mainHeaders(), tree: { length: 524288, depth: 2 } })],
        note: 'a tree.depth the tree doesn\'t give that address' },
      { id: 'readData-leaf-third-length', from: 'design 0015, forbidden alternatives', ...base, rule: 'value',
        calls: [...prefix, stream, refetch(4096), refetch(96), refetch(1000)], note: 'a leaf length no position gives it' },
    ],
  };
}

/**
 * A leaf whose own span is large: a root over a 4,096-byte leaf and W, a
 * chunk of two references with span 8,192, which its parent gives 64 bytes,
 * so it is a logical leaf and nothing inside it is admitted.
 */
function leafWithLargeSpan(env) {
  const { core } = env;
  const head = content('swarm-grammar/leaf-head', 4096);
  const inner = [content('swarm-grammar/inner-1', 4096), content('swarm-grammar/inner-2', 4096)]
    .map((d) => core.makeContentAddressedChunk(d).address.toHex());
  const wPayload = Buffer.concat(inner.map((a) => Buffer.from(a, 'hex')));
  const w = core.makeContentAddressedChunk(wPayload, 8192n).address.toHex();
  const headAddress = core.makeContentAddressedChunk(head).address.toHex();
  const n = 4096 + 64;
  const rootPayload = Buffer.concat([Buffer.from(headAddress, 'hex'), Buffer.from(w, 'hex')]);
  const root = core.makeContentAddressedChunk(rootPayload, BigInt(n)).address.toHex();
  const params = { object: [['reference', { string: root }]] };
  const rootCall = call('chunk', 'GET', `/chunks/${root}`, { headers: mainHeaders(), reply: { status: 200, body: { base64: b64(Buffer.concat([u64le(n), rootPayload])) } } });
  const base = { row: 'readData', key: C.ORIGIN, params, ready: { check: 'reachable', ok: true } };
  return {
    honest: [{ id: 'readData-logical-leaf-refetched', from: 'design 0015, Values main derives (a logical leaf)', ...base, calls: [rootCall,
      call('bytes', 'GET', `/bytes/${root}`, { headers: mainHeaders([['range', `bytes=0-${n - 1}`]]), maxBytes: n, reply: { status: 206 } }),
      call('chunk', 'GET', `/chunks/${w}`, { headers: mainHeaders(), tree: { length: 64, depth: 1 },
        reply: { status: 200, body: { base64: b64(Buffer.concat([u64le(8192), wPayload])) } } })] }],
    forbidden: [{ id: 'readData-slot-inside-a-logical-leaf', from: 'design 0015, forbidden alternatives', ...base, rule: 'value',
      calls: [rootCall, call('chunk', 'GET', `/chunks/${w}`, { headers: mainHeaders(), tree: { length: 64, depth: 1 },
        reply: { status: 200, body: { base64: b64(Buffer.concat([u64le(8192), wPayload])) } } }),
      call('chunk', 'GET', `/chunks/${inner[0]}`, { headers: mainHeaders(), tree: { length: 4096, depth: 2 } })],
      note: 'a slot inside a logical leaf whose own span is large' }],
  };
}

/** main's own rows (`swarm.publish`, `swarm.feed`, `swarm.stamps`, `swarm.upload_status`), from publish-service.js and feed-service.js. */
async function mainRows(env) {
  const out = [];
  const record = async (id, row, params, nodeSpec, fn) => {
    const requests = await withReference(env, { node: nodeSpec }, async (ref, node, world) => {
      await fn(ref, world);
      return node.requests.map((r) => ({ ...requestRecord(r, node), raw: r }));
    });
    const calls = requests.map((r) => {
      const form = formOf({ ...r.raw, headers: r.headers ?? [] }) ?? 'none';
      const c = coreCall({ ...r, status: r.status }, form);
      return c;
    });
    out.push({ id, row, from: 'publish-service.js / feed-service.js at the swarm reference', params, calls });
  };
  const stamps = { stamps: C.STAMPS.usable };
  await record('swarm.publish-data-default', 'swarm.publish:data,file', { kind: 'data', parts: [{ bytes: 5 }] }, stamps,
    (ref) => ref.publishService.publishData(Buffer.from('hello')));
  await record('swarm.publish-data-batch-encrypt', 'swarm.publish:data,file', { kind: 'data', parts: [{ bytes: 5 }], batch: C.BATCH_B, encrypt: true }, stamps,
    (ref) => ref.publishService.publishData(Buffer.from('hello'), { batchId: C.BATCH_B, encrypt: true, name: 'draft.md', contentType: 'text/markdown' }));
  await record('swarm.publish-file-default', 'swarm.publish:data,file', { kind: 'file', parts: [{ bytes: 9 }], name: 'notes.txt' }, stamps, (ref, world) => {
    const file = path.join(world.dir, 'notes.txt');
    fs.writeFileSync(file, 'the notes');
    return ref.publishService.publishFile(file);
  });
  await record('swarm.publish-collection-index-default', 'swarm.publish:collection', { kind: 'collection', parts: [{ path: 'index.html', bytes: 4 }, { path: 'a/b.txt', bytes: 1 }] },
    stamps, (ref) => ref.publishService.publishCollection([{ path: 'index.html', bytes: Buffer.from('home') }, { path: 'a/b.txt', bytes: Buffer.from('b') }]));
  await record('swarm.publish-collection-batch-encrypt', 'swarm.publish:collection', { kind: 'collection', parts: [{ path: 'x.txt', bytes: 1 }], batch: C.BATCH_B, encrypt: true },
    stamps, (ref) => ref.publishService.publishCollection([{ path: 'x.txt', bytes: Buffer.from('x') }], { batchId: C.BATCH_B, encrypt: true, indexDocument: 'x.txt' }));
  const signer = async (ref) => ref.load('./swarm-signer.js').resolveSwarmSigner({ mode: 'bee-wallet' });
  const agentTopic = 'freedom-agent/publications';
  await record('swarm.feed-create-batch', 'swarm.feed:create', { op: 'create', key: { kind: 'bee_wallet' }, topic: env.beeJs.Topic.fromString(agentTopic).toHex(), batch: C.BATCH_B },
    stamps, async (ref) => ref.feedService.createFeed(await signer(ref), agentTopic, C.BATCH_B));
  await record('swarm.feed-update-min-index', 'swarm.feed:update', { op: 'update', key: { kind: 'bee_wallet' }, topic: env.beeJs.Topic.fromString(agentTopic).toHex(),
    reference: C.REF, min_index: 9 }, { ...stamps, latest: [{ key: 'bee', topic: agentTopic, reply: { status: 200,
    headers: { 'swarm-feed-index': '0000000000000002', 'swarm-feed-index-next': '0000000000000003' }, body_utf8: 'x' } }] },
  async (ref) => ref.feedService.updateFeed(await signer(ref), agentTopic, C.REF, undefined, { minIndex: 9 }));
  await record('swarm.stamps-list', 'swarm.stamps', {}, stamps, (ref) => ref.swarmService.getBee().stamp.getAll());
  await record('swarm.upload_status', 'swarm.upload_status', { tag_uid: 101 }, { tags: { 101: { uid: 101, split: 1, seen: 0, stored: 1, sent: 1, synced: 1, address: 'ab'.repeat(32), startedAt: '2026-01-01T00:00:00Z' } } },
    (ref) => ref.publishService.getUploadStatus(101));
  // The feed_head the core sends in updateFeed's place of the whole lookup.
  for (const s of out) {
    s.calls = s.calls.map((c) => (c.form === 'feed_latest' && s.row === 'swarm.feed:update'
      ? { ...c, form: 'feed_head', headers: mainHeaders([['swarm-only-root-chunk', 'true']]), reply: { status: 200, headers: {
        'swarm-feed-index': '0000000000000002', 'swarm-feed-index-next': '0000000000000003' } } } : c));
  }
  return out;
}

/** Each row's nearest wrong calls (design 0015, the forbidden alternatives), from honest scenarios. */
function forbiddenFrom(honest, env) {
  const byId = new Map(honest.map((s) => [s.id, s]));
  const out = [];
  const add = (id, fromId, rule, note, edit) => {
    const base = byId.get(fromId);
    if (!base) throw new Error(`forbidden ${id}: no honest scenario ${fromId}`);
    const calls = structuredClone(base.calls);
    const scenario = { id, row: base.row, from: `honest/${fromId}`, key: base.key, params: base.params, ...(base.ready ? { ready: base.ready } : {}), rule, note };
    scenario.calls = edit(calls, base) || calls;
    // The refused call is the last; it has no reply.
    delete scenario.calls.at(-1).reply;
    out.push(scenario);
  };
  const last = (calls) => calls.at(-1);
  const zero = '00'.repeat(32);
  // readChunk: each other form, another or upper-case address, a retrieval header, a second call.
  add('readChunk-other-address', 'read-chunk-found', 'value', 'another address than params.reference', (calls) => { last(calls).path = `/chunks/${'ab'.repeat(32)}`; });
  add('readChunk-upper-case', 'read-chunk-found', 'value', 'the address not lowercased', (calls) => { last(calls).path = last(calls).path.toUpperCase().replace('/CHUNKS/', '/chunks/'); });
  add('readChunk-retrieval-header', 'read-chunk-found', 'header', 'a retrieval header on chunk', (calls) => { last(calls).headers.push(['swarm-redundancy-strategy', '3']); });
  add('readChunk-second-chunk', 'read-chunk-found', 'count', 'a second chunk', (calls) => [...calls, structuredClone(last(calls))]);
  for (const [form, method, p] of [['bzz_file', 'POST', '/bzz'], ['stamps', 'GET', '/stamps'], ['addresses', 'GET', '/addresses'],
    ['soc_up', 'POST', `/soc/${'ab'.repeat(20)}/${'cd'.repeat(32)}`], ['pss_send', 'POST', `/pss/send/${'ab'.repeat(32)}/abcd`],
    ['feed_latest', 'GET', `/feeds/${'ab'.repeat(20)}/${'cd'.repeat(32)}`]]) {
    add(`readChunk-cross-${form}`, 'read-chunk-found', 'form', `${form} under readChunk`, () => [{ form, method, path: p, headers: mainHeaders() }]);
  }
  add('readSingleOwnerChunk-other-address', 'read-soc-by-address', 'value', 'another address than params.address', (calls) => { last(calls).path = `/chunks/${'ab'.repeat(32)}`; });
  // readData.
  add('readData-unranged-bytes', 'read-data-4097', 'header', 'an unranged bytes (the reference\'s join)', (calls) => {
    last(calls).headers = last(calls).headers.filter(([n]) => n !== 'range');
  });
  add('readData-other-range', 'read-data-4097', 'header', 'a range other than bytes=0-<n − 1>', (calls) => {
    last(calls).headers = last(calls).headers.map(([n, v]) => (n === 'range' ? [n, 'bytes=0-4095'] : [n, v]));
  });
  add('readData-other-max-bytes', 'read-data-4097', 'value', 'a max_bytes other than n', (calls) => { last(calls).max_bytes = 4098; });
  add('readData-bytes-for-one-chunk', 'read-data-4096', 'order', 'a bytes for data of 4,096 bytes or less', (calls) => [...calls,
    call('bytes', 'GET', calls[0].path.replace('/chunks/', '/bytes/'), { headers: mainHeaders([['range', 'bytes=0-4095']]), maxBytes: 4096 })]);
  add('readData-retrieval-header', 'read-data-4097', 'header', 'a retrieval header on bytes', (calls) => { last(calls).headers.push(['swarm-chunk-retrieval-timeout', '30s']); });
  add('readData-padding-address', 'read-data-524289', 'value', 'a chunk at the all-zero padding address', (calls) => [calls[0],
    call('chunk', 'GET', `/chunks/${zero}`, { headers: mainHeaders(), tree: { length: 4096, depth: 1 } })]);
  add('readData-unnamed-address', 'read-data-524289', 'value', 'a chunk at an address no returned chunk names', (calls) => [calls[0],
    call('chunk', 'GET', `/chunks/${'ab'.repeat(32)}`, { headers: mainHeaders(), tree: { length: 524288, depth: 1 } })]);
  add('readData-more-than-named', 'read-data-524289', 'count', 'a chunk more times than the tree names it', (calls) => [...calls.slice(0, -1),
    structuredClone(calls[1]), structuredClone(calls[1])]);
  const coded = honest.find((s) => s.id === 'readData-walk-file-524289-rs2');
  if (coded) {
    const parity = env.parityOf('file-524289-rs2');
    out.push({ id: 'readData-parity-address', row: 'readData', from: 'honest/readData-walk-file-524289-rs2', key: coded.key, params: coded.params,
      ready: coded.ready, rule: 'value', note: 'a chunk at a parity address',
      calls: [structuredClone(coded.calls[0]), call('chunk', 'GET', `/chunks/${parity}`, { headers: mainHeaders(), tree: { length: 4096, depth: 1 } })] });
  }
  // readFeedEntry.
  add('readFeedEntry-bytes-other-address', 'read-feed-index-4097', 'value', 'a feed read\'s bytes at another address than the wrapped chunk\'s',
    (calls) => { last(calls).path = `/bytes/${'ab'.repeat(32)}`; });
  add('readFeedEntry-bytes-for-one-chunk', 'read-feed-index-inline', 'order', 'a bytes for an entry of 4,096 bytes or less', (calls) => [...calls,
    call('bytes', 'GET', `/bytes/${'ab'.repeat(32)}`, { headers: mainHeaders(), maxBytes: 10 })]);
  add('readFeedEntry-feed-other-index', 'read-feed-index-inline', 'value', 'a feed chunk whose feed names another index than params.index',
    (calls) => { last(calls).feed = { ...last(calls).feed, index: last(calls).feed.index + 1 }; });
  add('readFeedEntry-feed-other-owner', 'read-feed-index-inline', 'value', 'a feed chunk whose feed names another owner than the parent\'s',
    (calls) => { last(calls).feed = { ...last(calls).feed, owner: 'ab'.repeat(20) }; });
  add('readFeedEntry-path-not-feed', 'read-feed-index-inline', 'value', 'a feed chunk whose path isn\'t the address main builds from feed',
    (calls) => { last(calls).path = `/chunks/${'ab'.repeat(32)}`; });
  add('readFeedEntry-whole-latest-for-index', 'read-feed-index-inline', 'form', 'a whole feed_latest for an index lookup',
    (calls) => [call('feed_latest', 'GET', `/feeds/${calls[0].feed.owner}/${'cd'.repeat(32)}`, { headers: mainHeaders() })]);
  // Writes.
  add('publishData-second-stamps', 'publish-data-string', 'count', 'a second /stamps', (calls) => [calls[0], structuredClone(calls[0])]);
  add('publishData-upload-before-stamps', 'publish-data-string', 'order', 'an upload before its stamps', (calls) => [calls[1]]);
  add('publishData-bzz-tar', 'publish-data-string', 'form', 'bzz_tar under publishData', (calls) => {
    last(calls).form = 'bzz_tar';
    last(calls).headers.push(['swarm-collection', 'true']);
  });
  add('publishData-chunk-up', 'publish-data-string', 'form', 'chunk_up under publishData', (calls) => [calls[0],
    call('chunk_up', 'POST', '/chunks', { headers: mainHeaders([['content-type', 'application/octet-stream']]), body: Buffer.alloc(9) })]);
  add('publishData-deferred', 'publish-data-string', 'value', 'swarm-deferred-upload: true for publishData', (calls) => {
    last(calls).headers = last(calls).headers.map(([n, v]) => (n === 'swarm-deferred-upload' ? [n, 'true'] : [n, v]));
  });
  add('publishData-encrypt', 'publish-data-string', 'header', 'swarm-encrypt under swarm.request', (calls) => { last(calls).headers.push(['swarm-encrypt', 'true']); });
  add('publishData-other-content-type', 'publish-data-string', 'value', 'another content-type than the page\'s', (calls) => {
    last(calls).headers = last(calls).headers.map(([n, v]) => (n === 'content-type' ? [n, 'text/plain'] : [n, v]));
  });
  add('publishData-other-length', 'publish-data-string', 'body', 'a body of another length than the data\'s', (calls) => {
    last(calls).body = { bytes: last(calls).body.bytes + 1, base64: b64(Buffer.concat([Buffer.from(last(calls).body.base64, 'base64'), Buffer.from('!')])) };
  });
  add('publishData-other-bytes', 'publish-data-string', 'body', 'base64 bytes that differ from the page\'s', (calls) => {
    const bytes = Buffer.from(last(calls).body.base64, 'base64');
    bytes[0] ^= 1;
    last(calls).body = { bytes: bytes.length, base64: b64(bytes) };
  });
  add('publishData-second-upload', 'publish-data-string', 'count', 'a second upload', (calls) => [...calls, structuredClone(last(calls))]);
  add('publishFiles-collection-header-missing-index', 'publish-files-nested', 'header', 'another index document than the row binds', (calls) => {
    last(calls).headers = last(calls).headers.map(([n, v]) => (n === 'swarm-index-document' ? [n, 'assets/app.js'] : [n, v]));
  });
  add('writeSingleOwnerChunk-feed-manifest', 'write-soc-one-byte', 'form', 'feed_manifest under writeSingleOwnerChunk', (calls) => [calls[0],
    call('feed_manifest', 'POST', `/feeds/${'ab'.repeat(20)}/${'cd'.repeat(32)}`, { headers: mainHeaders() })]);
  add('writeSingleOwnerChunk-bytes-up', 'write-soc-one-byte', 'form', 'bytes_up under writeSingleOwnerChunk', (calls) => [calls[0],
    call('bytes_up', 'POST', '/bytes', { headers: mainHeaders([['content-type', 'application/octet-stream']]), body: Buffer.from('x') })]);
  add('writeSingleOwnerChunk-other-id', 'write-soc-one-byte', 'value', 'a soc_up with another <id>', (calls) => {
    last(calls).path = last(calls).path.replace(/[0-9a-f]{64}$/, 'ab'.repeat(32));
  });
  add('getUploadStatus-other-tag', 'upload-status-in-progress/1', 'value', 'another tag than the page\'s', (calls) => { last(calls).path = '/tags/102'; });
  add('writeFeedEntry-soc-before-lookup', 'write-feed-string', 'order', 'a feed write\'s soc_up before its index lookup', (calls) => [calls[0], last(calls)]);
  add('writeFeedEntry-bytes-up-for-one-chunk', 'write-feed-4096', 'order', 'a bytes_up for a feed entry of 4,096 bytes or less', (calls) => [...calls.slice(0, -1),
    call('bytes_up', 'POST', '/bytes', { headers: mainHeaders([['content-type', 'application/octet-stream']]), body: Buffer.alloc(4096) })]);
  add('writeFeedEntry-read-root-back', 'write-feed-4097', 'order', 'GET /chunks after a /bytes upload', (calls) => {
    const up = calls.findIndex((c) => c.form === 'bytes_up');
    return [...calls.slice(0, up + 1), call('chunk', 'GET', `/chunks/${'ab'.repeat(32)}`, { headers: mainHeaders() })];
  });
  add('writeFeedEntry-soc-before-bytes-up', 'write-feed-4097', 'order', 'a large feed write\'s soc_up before its bytes_up', (calls) => calls.filter((c) => c.form !== 'bytes_up'));
  add('writeFeedEntry-other-root', 'write-feed-4097', 'body', 'a large feed write\'s soc_up whose root isn\'t bytes_up\'s reference', (calls) => {
    const body = Buffer.from(last(calls).body.base64, 'base64');
    body[body.length - 1] ^= 1;
    last(calls).body = { bytes: body.length, base64: b64(body) };
  });
  add('writeFeedEntry-other-id', 'write-feed-string', 'value', 'a soc_up with another <id> than main derives', (calls) => {
    last(calls).path = last(calls).path.replace(/[0-9a-f]{64}$/, 'ab'.repeat(32));
  });
  add('writeFeedEntry-other-owner', 'write-feed-string', 'value', 'a second <o> within one request', (calls) => {
    last(calls).path = last(calls).path.replace(/\/soc\/[0-9a-f]{40}\//, `/soc/${'ab'.repeat(20)}/`);
  });
  add('writeFeedEntry-head-query-form', 'write-feed-string', 'query', 'feed_head\'s query form ?Swarm-Only-Root-Chunk=true', (calls) => {
    const head = calls.find((c) => c.form === 'feed_head');
    head.headers = head.headers.filter(([n]) => n !== 'swarm-only-root-chunk');
    head.query = [['Swarm-Only-Root-Chunk', 'true']];
    return calls.slice(0, calls.indexOf(head) + 1);
  });
  add('writeFeedEntry-whole-latest-for-index', 'write-feed-string', 'form', 'a whole feed_latest for an index lookup', (calls) => {
    const head = calls.find((c) => c.form === 'feed_head');
    head.form = 'feed_latest';
    head.headers = head.headers.filter(([n]) => n !== 'swarm-only-root-chunk');
    return calls.slice(0, calls.indexOf(head) + 1);
  });
  add('updateFeed-probe-wrong-index', 'update-feed-head-7', 'value', 'a probe chunk at another index than the probe asks next', (calls) => {
    const probes = calls.filter((c) => c.feed);
    const third = probes[2];
    third.feed = { ...third.feed, index: third.feed.index + 1 };
    third.path = `/chunks/${env.feedAddressFor(third.feed)}`;
    return calls.slice(0, calls.indexOf(third) + 1);
  });
  add('updateFeed-83rd-probe', 'update-feed-head-81-reads', 'count', 'an 83rd probe chunk', (calls) => {
    const probes = calls.filter((c) => c.feed);
    const extra = Array.from({ length: 83 - probes.length }, () => structuredClone(probes.at(-1)));
    return [...calls.slice(0, calls.indexOf(probes.at(-1)) + 1), ...extra];
  });
  add('sendPss-128-hex-recipient', 'send-pss-sent', 'query', 'the 128-hex PSS recipient (F-9)', (calls) => {
    last(calls).query = [['recipient', 'ab'.repeat(64)]];
  });
  add('sendPss-upper-case-targets', 'send-pss-sent', 'value', 'upper-case <x>', (calls) => { last(calls).path = last(calls).path.replace(/\/[0-9a-f]+$/, (m) => m.toUpperCase()); });
  add('sendPss-other-topic', 'send-pss-sent', 'value', 'another topic than the row binds', (calls) => {
    last(calls).path = last(calls).path.replace(/send\/[0-9a-f]{64}/, `send/${'ab'.repeat(32)}`);
  });
  add('sendGsoc-other-id', 'send-gsoc-sent', 'value', 'a soc_up with another <id> than keccak256(topic)', (calls) => {
    last(calls).path = last(calls).path.replace(/[0-9a-f]{64}$/, 'ab'.repeat(32));
  });
  add('swarm.publish-batch-other', 'swarm.publish-data-batch-encrypt', 'value', 'a swarm-postage-batch-id other than the parent\'s batch', (calls) => {
    last(calls).headers = last(calls).headers.map(([n, v]) => (n === 'swarm-postage-batch-id' ? [n, C.BATCH_A] : [n, v]));
  });
  add('swarm.publish-batch-and-stamps', 'swarm.publish-data-batch-encrypt', 'order', 'a /stamps when the parent named its batch', (calls) => [
    call('stamps', 'GET', '/stamps', { headers: mainHeaders() }), ...calls]);
  add('swarm.publish-encrypt-not-asked', 'swarm.publish-data-default', 'header', 'swarm-encrypt under swarm.publish without encrypt', (calls) => {
    last(calls).headers.push(['swarm-encrypt', 'true']);
  });
  add('swarm.stamps-write', 'swarm.stamps-list', 'form', 'any write under swarm.stamps', () => [call('chunk_up', 'POST', '/chunks',
    { headers: mainHeaders([['content-type', 'application/octet-stream']]), body: Buffer.alloc(9) })]);
  return out;
}

async function buildGrammar(env, methods, nodeBodies, dwebVerify, meta) {
  await prepareWalks(env, methods);
  const fromMethods = honestFromMethods(env, methods, nodeBodies);
  const walks = dwebWalks(env, dwebVerify);
  const two = twoPositions(env);
  const leaf = leafWithLargeSpan(env);
  const main = await mainRows(env);
  const honest = [...fromMethods, ...walks, ...two.honest, ...leaf.honest, ...main];
  const forbidden = [...forbiddenFrom(honest, env), ...two.forbidden, ...leaf.forbidden];
  // What the check found: every recorded request, by row and by form or deviation.
  const checked = {};
  for (const c of methods) {
    for (const step of c.steps) {
      const row = rowOf(step) ?? '(no row)';
      for (const r of step.requests) {
        const key = r.form ? `form ${r.form}` : (r.deviation ? `deviation ${r.deviation}` : `ready ${r.ready}`);
        checked[row] ||= {};
        checked[row][key] = (checked[row][key] || 0) + 1;
      }
    }
  }
  return {
    meta,
    formats: GRAMMAR_FORMATS,
    values: VALUES,
    main_headers: MAIN_HEADERS,
    reply_headers: { read: ['content-type', 'content-length', 'swarm-tag', 'swarm-feed-index', 'swarm-feed-index-next'], max: 8, name_bytes: 64,
      value_bytes: 1024, reason_bytes: 1024 },
    error_reply: { whole: 8192 },
    failed: ['unreachable', 'error', 'aborted', 'too_large', 'busy'],
    rules: ['form', 'order', 'count', 'value', 'header', 'query', 'body', 'ended'],
    forms: FORMS,
    rows: ROWS,
    deviation_requests: DEVIATION_REQUESTS,
    checked,
    honest,
    forbidden,
  };
}

const GRAMMAR_FORMATS = {
  forms: 'design 0015\'s shell.swarm_api forms: method, path (its values named as in `values`), query names in order, request headers '
    + '[name, value, when] (when: row, the row says whether; publish, under swarm.publish only; soc-raw, writeSingleOwnerChunk only), the body\'s kinds '
    + '(base64 at most 64 KiB, or stream) and byte bounds, and the reply (whole with its cap, or a stream under max_bytes). Main adds main_headers to every call.',
  rows: 'each parent\'s ready check and calls in order: forms, count [min, max], when, and the values the row binds (the design\'s text). '
    + 'readFeedEntry_index and readFeedEntry_latest are readFeedEntry with and without params.index.',
  deviation_requests: 'the reference\'s requests the core drops, by deviation id; vectors/swarm.json marks each such request `deviation`.',
  checked: 'the requests of every vectors/swarm.json methods case, by row: each matched its row as `form <name>`, was its ready probe, or was one of a named deviation\'s requests.',
  scenarios: 'honest and forbidden: { id, row, from, key (the page key), params (swarm.json\'s typed form, or main\'s own params), ready, calls }. '
    + 'A call: form, method, path, query, headers (as main sends them, main_headers included), body ({ bytes, base64 } or { bytes, sha256 }), '
    + 'max_bytes, feed { owner, index }, tree { length, depth }, and reply (status, headers, body { base64 } or body_ref naming the chunk store it comes from, '
    + 'such as dweb-verify.json swarm.chunks). Every call of an honest scenario is admitted in order; a forbidden scenario\'s calls before its last are '
    + 'admitted and its last is refused before any dial with `rule`.',
  gaps: 'the design\'s honest and forbidden tree cases at depths 6 to 8 (and a zero-length child) can\'t occur under readData: with n at most B = 5 MiB, '
    + '0009\'s geometry puts every leaf at depth 2 or less, so they are left out here (see the PR\'s questions).',
};

module.exports = { buildGrammar };
