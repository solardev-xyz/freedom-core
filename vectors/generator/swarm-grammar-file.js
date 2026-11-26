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
const { FORMS, ROWS, VALUES, DEVIATION_REQUESTS, MAIN_HEADERS, MAX_PROBE_READS, formOf, feedAddress, feedIdentifierHex } = require('./swarm-grammar');
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
        // A subscribe-proxy case's ready check answers as main answers the
        // core's (session.subscribe_check): refused, the parent makes no call.
        ...(ready ? { ready: { check: ready, ...(ready === 'subscribe' && c.session ? c.session.subscribe_check : { ok: true }) } } : {}),
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
  // A root whose span carries a redundancy level: design 0009's level-1
  // tree, its two leaves read as one stream.
  walks.set(env.levelRoot.address, walkOf(env.levelRoot.address, env.levelRoot.size, []));
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

/**
 * The deep trees and an over-full intermediate (design 0015, the honest
 * calls and forbidden alternatives): no honest splitter writes them inside
 * readData's 5 MiB, but a node can serve them. Every chunk is core-sdk's
 * (makeContentAddressedChunk over the payload and span given), so each
 * address is the reference's own.
 * - A lone-reference wrapper (one reference, its child's span, as Ant writes
 *   one) gives its child its whole length, one level deeper, so a chain of
 *   them reaches any depth within the file's length.
 * - Tree A: a root of 1 MiB over [W5, W6], where W1 = wrap(Y), W(k+1) =
 *   wrap(Wk), Y = wrap(Z) and Z an intermediate of 128 leaves: Y sits at
 *   depths 6 and 7 (each wrapper at two depths too), the depth-6 copy's
 *   intermediate child Z at depth 7, and the depth-7 copy's at depth 8,
 *   where the walk ends unverifiable instead of fetching it.
 * - Tree B: seven wrappers from the root down, then X, an intermediate of
 *   128 leaves, at depth 7: its leaves sit at depth 8, and one is fetched
 *   again after the stream.
 * - Tree E: eight wrappers, so X is an intermediate at depth 8.
 * - Tree D: 8,192 bytes under a root of four references: the last two get
 *   no length (zero-length children).
 */
function deepTrees(env) {
  const { core } = env;
  const chunkOf = (payload, span) => {
    const address = core.makeContentAddressedChunk(payload, BigInt(span)).address.toHex();
    return { address, span, wire: Buffer.concat([u64le(span), payload]) };
  };
  const leavesOf = (seed, n) => {
    const data = content(seed, n);
    const out = [];
    for (let at = 0; at < n; at += 4096) out.push(chunkOf(data.subarray(at, Math.min(n, at + 4096)), Math.min(4096, n - at)));
    return out;
  };
  const over = (children, span) => chunkOf(Buffer.concat(children.map((c) => Buffer.from(c.address, 'hex'))), span);
  const wrap = (child) => over([child], child.span);
  const get = (c, length, depth) => call('chunk', 'GET', `/chunks/${c.address}`, { headers: mainHeaders(), ...(depth === 0 ? {} : { tree: { length, depth } }),
    reply: { status: 200, body: { base64: b64(c.wire) } } });
  const ask = (c, length, depth) => call('chunk', 'GET', `/chunks/${c.address}`, { headers: mainHeaders(), tree: { length, depth } });
  const stream = (root, n) => call('bytes', 'GET', `/bytes/${root.address}`, { headers: mainHeaders([['range', `bytes=0-${n - 1}`]]), maxBytes: n,
    reply: { status: 206 } });
  const scenario = (id, root, n, note) => ({ id, row: 'readData', from: 'design 0015, the honest calls and forbidden alternatives (deep trees)',
    key: C.ORIGIN, params: { object: [['reference', { string: root.address }]] }, ready: { check: 'reachable', ok: true }, note });
  const L = 524288;

  // Tree A.
  const z = over(leavesOf('swarm-grammar/deep-a', L), L);
  const y = wrap(z);
  const w = [y];
  for (let k = 1; k <= 6; k++) w.push(wrap(w[k - 1]));
  const rootA = over([w[5], w[6]], 2 * L);
  // Breadth first: depth d holds W(6 − d) under W5 and W(7 − d) under W6.
  const callsA = [get(rootA, 2 * L, 0)];
  for (let d = 1; d <= 5; d++) callsA.push(get(w[6 - d], L, d), get(w[7 - d], L, d));
  callsA.push(get(y, L, 6), get(w[1], L, 6), get(z, L, 7), get(y, L, 7));
  // Tree B.
  const x = over(leavesOf('swarm-grammar/deep-b', L), L);
  const chainB = [x];
  for (let k = 1; k <= 7; k++) chainB.push(wrap(chainB[k - 1]));
  const rootB = chainB[7];
  const callsB = [get(rootB, L, 0)];
  for (let d = 1; d <= 6; d++) callsB.push(get(chainB[7 - d], L, d));
  callsB.push(get(x, L, 7), stream(rootB, L));
  const leafB = leavesOf('swarm-grammar/deep-b', L)[0];
  // Tree E: one more wrapper.
  const rootE = wrap(rootB);
  const callsE = [get(rootE, L, 0)];
  for (let d = 1; d <= 7; d++) callsE.push(get(chainB[8 - d], L, d));
  // Tree D.
  const [d0, d1] = leavesOf('swarm-grammar/over-full', 8192);
  const [e0, e1] = leavesOf('swarm-grammar/over-full-extra', 8192);
  const rootD = over([d0, d1, e0, e1], 8192);
  const callsD = [get(rootD, 8192, 0), stream(rootD, 8192)];
  return {
    honest: [
      { ...scenario('readData-one-chunk-at-depths-6-and-7', rootA, 2 * L, 'Y fetched at depths 6 and 7, Z (the depth-6 copy\'s intermediate child) at 7; '
        + 'the walk ends unverifiable at Z\'s depth-8 occurrence'), calls: callsA },
      { ...scenario('readData-leaf-at-depth-8-fetched-again', rootB, L, 'seven wrappers, X at depth 7, its first leaf fetched again at depth 8'),
        calls: [...callsB, get(leafB, 4096, 8)] },
      { ...scenario('readData-over-full-intermediate', rootD, 8192, 'a root of four references over 8,192 bytes: two leaves, then two zero-length children'),
        calls: [...callsD, get(d1, 4096, 1)] },
    ],
    forbidden: [
      { ...scenario('readData-depth-7-copy-child-at-depth-8', rootA, 2 * L, 'the depth-7 copy\'s intermediate child, at depth 8'), rule: 'value',
        calls: [...callsA, ask(z, L, 8)] },
      { ...scenario('readData-intermediate-at-depth-8', rootE, L, 'an intermediate at depth 8 (eight wrappers above it)'), rule: 'value',
        calls: [...callsE, ask(x, L, 8)] },
      { ...scenario('readData-zero-length-child', rootD, 8192, 'a zero-length child: an intermediate with more references than its length needs'),
        rule: 'value', calls: [callsD[0], ask(e0, 0, 1)] },
    ],
  };
}

// 0009's geometry, as the design's rules read an intermediate main returned
// (fc_swarm::tree): the data references before the trailing zeros, the
// first children a full branch each, the last the rest.
const CHUNK = 4096;
const MAX_REFS = 128;
const MAX_DEPTH = 8;

function branchSize(refs, span) {
  let branch = BigInt(CHUNK);
  for (;;) {
    const before = branch * BigInt(refs - 1);
    if (span <= before || span - before <= branch) return branch;
    branch *= BigInt(MAX_REFS);
  }
}

/** The data children of `wire` read as an intermediate of `length` bytes, or null where the core refuses it; `level` > 0 throws (not modelled). */
function dataChildren(wire, length) {
  const level = wire[7] > 128 ? wire[7] & 0x7f : 0;
  if (level > 0) throw Object.assign(new Error('a redundancy level'), { level });
  const payload = wire.subarray(8);
  if (payload.length % 32 !== 0) return null;
  let refs = payload.length / 32;
  while (refs > 0 && payload.subarray((refs - 1) * 32, refs * 32).every((b) => b === 0)) refs -= 1;
  if (refs === 0 || refs > MAX_REFS) return null;
  const span = BigInt(length);
  const branch = branchSize(refs, span);
  const out = [];
  for (let i = 0; i < refs; i++) {
    const before = branch * BigInt(i);
    const rest = span > before ? span - before : 0n;
    out.push({ address: payload.subarray(i * 32, i * 32 + 32).toString('hex'), length: Number(i + 1 === refs ? rest : (rest < branch ? rest : branch)) });
  }
  return out;
}

/**
 * Plays a readData scenario against the design's admission rules (Values
 * main derives, the file tree's data children), over the replies the
 * scenario gives main: the root at params.reference; one bytes, ranged
 * 0 to n − 1 with max_bytes n, only when n is over 4,096 bytes; and each
 * later chunk an unfetched slot of an occurrence (address, logical length,
 * depth) that an intermediate main returned names, a child that isn't a leaf
 * named only above depth 8. Returns the first call refused and its rule, or
 * null when every call is admitted; `skip` for a tree with a redundancy
 * level, whose parities this check doesn't model.
 */
function admitReadData(scenario, bodyOf) {
  const reference = Object.fromEntries(scenario.params.object)['reference'].string.toLowerCase();
  const slots = new Map();
  const named = new Set();
  const key = (address, length, depth) => `${address}/${length}/${depth}`;
  const allowedHeaders = (call, extra) => call.headers.every(([n, v]) => MAIN_HEADERS[n] === v || extra.includes(n));
  let n = null;
  let streamed = false;
  const parse = (wire, length, depth) => {
    if (length <= CHUNK) return;
    for (const child of dataChildren(wire, length) || []) {
      if (child.length === 0) continue;
      if (child.length > CHUNK && depth + 1 >= MAX_DEPTH) continue;
      const k = key(child.address, child.length, depth + 1);
      named.add(k);
      slots.set(k, (slots.get(k) || 0) + 1);
    }
  };
  try {
    for (const [i, c] of scenario.calls.entries()) {
      const refuse = (rule) => ({ at: i, rule });
      if (i === 0) {
        if (c.form !== 'chunk') return refuse('form');
        if (c.path !== `/chunks/${reference}` || c.tree) return refuse('value');
        if (!allowedHeaders(c, [])) return refuse('header');
        const wire = bodyOf(c);
        if (!wire) continue;
        const span = Buffer.from(wire.subarray(0, 8));
        if (span[7] > 128) throw Object.assign(new Error('a redundancy level'), { level: span[7] & 0x7f });
        n = Number(span.readBigUInt64LE(0));
        parse(wire, n, 0);
        continue;
      }
      if (c.form === 'bytes') {
        if (streamed) return refuse('count');
        if (!(n > CHUNK)) return refuse('order');
        if (c.path !== `/bytes/${reference}`) return refuse('value');
        if (!allowedHeaders(c, ['range'])) return refuse('header');
        if (!c.headers.some(([h, v]) => h === 'range' && v === `bytes=0-${n - 1}`)) return refuse('header');
        if (c.max_bytes !== n) return refuse('value');
        streamed = true;
        continue;
      }
      if (c.form !== 'chunk') return refuse('form');
      if (!allowedHeaders(c, [])) return refuse('header');
      if (!c.tree) return refuse('value');
      const address = c.path.slice('/chunks/'.length);
      const k = key(address, c.tree.length, c.tree.depth);
      if (!named.has(k)) return refuse('value');
      if (!(slots.get(k) > 0)) return refuse('count');
      slots.set(k, slots.get(k) - 1);
      const wire = bodyOf(c);
      if (wire) parse(wire, c.tree.length, c.tree.depth);
    }
  } catch (err) {
    if (err.level) return { skip: true };
    throw err;
  }
  return null;
}

/** Every readData scenario played against the admission rules: honest ones admitted whole, forbidden ones refused at their last call by their rule. */
function checkReadDataScenarios(honest, forbidden, dwebVerify) {
  const bodyOf = (c) => {
    if (c.reply?.body?.base64) return Buffer.from(c.reply.body.base64, 'base64');
    if (c.reply?.body_ref) return Buffer.from(dwebVerify.swarm.chunks[c.path.slice('/chunks/'.length)], 'base64');
    return null;
  };
  const out = { honest: 0, forbidden: 0, skipped: [] };
  for (const s of honest.filter((h) => h.row === 'readData')) {
    const verdict = admitReadData(s, bodyOf);
    if (verdict?.skip) {
      out.skipped.push(s.id);
      continue;
    }
    if (verdict) throw new Error(`honest ${s.id}: call ${verdict.at} refused (${verdict.rule})`);
    out.honest += 1;
  }
  for (const s of forbidden.filter((f) => f.row === 'readData')) {
    const verdict = admitReadData(s, bodyOf);
    if (verdict?.skip) {
      out.skipped.push(s.id);
      continue;
    }
    if (!verdict || verdict.at !== s.calls.length - 1 || verdict.rule !== s.rule) {
      throw new Error(`forbidden ${s.id}: ${verdict ? `call ${verdict.at} refused (${verdict.rule})` : 'every call admitted'}, `
        + `the scenario refuses call ${s.calls.length - 1} (${s.rule})`);
    }
    out.forbidden += 1;
  }
  return out;
}

/** main's own rows (`swarm.publish`, `swarm.feed`, `swarm.stamps`, `swarm.upload_status`), from publish-service.js and feed-service.js. */
async function mainRows(env) {
  const out = [];
  const record = async (id, row, params, nodeSpec, fn, parts) => {
    const requests = await withReference(env, { node: nodeSpec }, async (ref, node, world) => {
      await fn(ref, world);
      return node.requests.map((r) => ({ ...requestRecord(r, node), raw: r }));
    });
    const calls = requests.map((r) => {
      const form = formOf({ ...r.raw, headers: r.headers ?? [] }) ?? 'none';
      const c = coreCall({ ...r, status: r.status }, form);
      return c;
    });
    const indexHeaders = requests.map((r) => Object.fromEntries(Object.entries(r.raw.replyHeaders || {})
      .map(([n, v]) => [n.toLowerCase(), String(v)]).filter(([n]) => n.startsWith('swarm-feed-index'))));
    out.push({ id, row, from: 'publish-service.js / feed-service.js at the swarm reference', params, ...(parts ? { parts } : {}), calls,
      ...(row === 'swarm.feed:read' ? { indexHeaders } : {}) });
  };
  const stamps = { stamps: C.STAMPS.usable };
  // swarm.publish's params are main's own, whole, in the wire form
  // swarm.json's shell cases use (SWM-4's D5): every option the reference
  // was called with, pin and deferred, and each part as main sends it:
  // held bytes inline, a picked file's or a collection entry's as
  // { part: k }, its bytes in the scenario's `parts`.
  const inline = (bytes) => ({ bytes: bytes.length, base64: b64(bytes) });
  const streamed = (entries) => ({
    parts: entries.map(([p, bytes], k) => ({ ...(p === undefined ? {} : { path: p }), bytes: bytes.length, part: k })),
    bytes: entries.map(([, bytes]) => inline(bytes)),
  });
  const hello = Buffer.from('hello');
  await record('swarm.publish-data-default', 'swarm.publish:data,file', { kind: 'data', parts: [inline(hello)], pin: true, deferred: false }, stamps,
    (ref) => ref.publishService.publishData(hello));
  await record('swarm.publish-data-batch-encrypt', 'swarm.publish:data,file', { kind: 'data', parts: [inline(hello)], name: 'draft.md',
    content_type: 'text/markdown', encrypt: true, batch: C.BATCH_B, pin: true, deferred: false }, stamps,
  (ref) => ref.publishService.publishData(hello, { batchId: C.BATCH_B, encrypt: true, name: 'draft.md', contentType: 'text/markdown' }));
  const notes = streamed([[undefined, Buffer.from('the notes')]]);
  await record('swarm.publish-file-default', 'swarm.publish:data,file', { kind: 'file', parts: notes.parts, name: 'notes.txt', pin: true, deferred: true },
    stamps, (ref, world) => {
      const file = path.join(world.dir, 'notes.txt');
      fs.writeFileSync(file, 'the notes');
      return ref.publishService.publishFile(file);
    }, notes.bytes);
  const site = [['index.html', Buffer.from('home')], ['a/b.txt', Buffer.from('b')]];
  const siteParts = streamed(site);
  await record('swarm.publish-collection-index-default', 'swarm.publish:collection', { kind: 'collection', parts: siteParts.parts, pin: true, deferred: true },
    stamps, (ref) => ref.publishService.publishCollection(site.map(([p, bytes]) => ({ path: p, bytes }))), siteParts.bytes);
  const one = [['x.txt', Buffer.from('x')]];
  const oneParts = streamed(one);
  await record('swarm.publish-collection-batch-encrypt', 'swarm.publish:collection', { kind: 'collection', parts: oneParts.parts, index_document: 'x.txt',
    encrypt: true, batch: C.BATCH_B, pin: true, deferred: true }, stamps,
  (ref) => ref.publishService.publishCollection(one.map(([p, bytes]) => ({ path: p, bytes })), { batchId: C.BATCH_B, encrypt: true, indexDocument: 'x.txt' }),
  oneParts.bytes);
  const signer = async (ref) => ref.load('./swarm-signer.js').resolveSwarmSigner({ mode: 'bee-wallet' });
  const agentTopic = 'freedom-agent/publications';
  await record('swarm.feed-create-batch', 'swarm.feed:create', { op: 'create', key: { kind: 'bee_wallet' }, topic: env.beeJs.Topic.fromString(agentTopic).toHex(), batch: C.BATCH_B },
    stamps, async (ref) => ref.feedService.createFeed(await signer(ref), agentTopic, C.BATCH_B));
  await record('swarm.feed-update-min-index', 'swarm.feed:update', { op: 'update', key: { kind: 'bee_wallet' }, topic: env.beeJs.Topic.fromString(agentTopic).toHex(),
    reference: C.REF, min_index: 9 }, { ...stamps, latest: [{ key: 'bee', topic: agentTopic, reply: { status: 200,
    headers: { 'swarm-feed-index': '0000000000000002', 'swarm-feed-index-next': '0000000000000003' }, body_utf8: 'x' } }] },
  async (ref) => ref.feedService.updateFeed(await signer(ref), agentTopic, C.REF, undefined, { minIndex: 9 }));
  // readFeedState (swarm.feed's read): the lookup, then the head probe
  // after its 404.
  const readParams = { op: 'read', key: { kind: 'bee_wallet' }, topic: env.beeJs.Topic.fromString(agentTopic).toHex() };
  const beeOwner = env.keyOf('bee').address;
  const latest = (reply) => [{ key: 'bee', topic: agentTopic, reply }];
  const missing = { status: 404, json: { code: 404, message: 'Not Found' } };
  const readState = (ref) => ref.feedService.readFeedState(beeOwner, agentTopic);
  await record('swarm.feed-read-latest', 'swarm.feed:read', readParams, { latest: latest({ status: 200,
    headers: { 'swarm-feed-index': '0000000000000002', 'swarm-feed-index-next': '0000000000000003' }, body_utf8: 'x' }) }, readState);
  await record('swarm.feed-read-empty', 'swarm.feed:read', readParams, { latest: latest(missing),
    probes: [{ key: 'bee', topic: agentTopic, targets: [] }] }, readState);
  await record('swarm.feed-read-probe', 'swarm.feed:read', readParams, { latest: latest(missing),
    probes: [{ key: 'bee', topic: agentTopic, head: 4, targets: [5] }] }, readState);
  // A 500 is thrown with bee-js's text, with no probe.
  await record('swarm.feed-read-node-500', 'swarm.feed:read', readParams, { latest: latest({ status: 500, json: { code: 500, message: 'feed lookup failed' } }) },
    (ref) => readState(ref).then(() => {
      throw new Error('readFeedState answered a 500');
    }, (err) => {
      if (err?.status !== 500) throw err;
    }));
  await record('swarm.stamps-list', 'swarm.stamps', {}, stamps, (ref) => ref.swarmService.getBee().stamp.getAll());
  await record('swarm.upload_status', 'swarm.upload_status', { tag_uid: 101 }, { tags: { 101: { uid: 101, split: 1, seen: 0, stored: 1, sent: 1, synced: 1, address: 'ab'.repeat(32), startedAt: '2026-01-01T00:00:00Z' } } },
    (ref) => ref.publishService.getUploadStatus(101));
  // The feed_head the core sends in updateFeed's place of the whole lookup.
  for (const s of out) {
    s.calls = s.calls.map((c) => (c.form === 'feed_latest' && s.row === 'swarm.feed:update'
      ? { ...c, form: 'feed_head', headers: mainHeaders([['swarm-only-root-chunk', 'true']]), reply: { status: 200, headers: {
        'swarm-feed-index': '0000000000000002', 'swarm-feed-index-next': '0000000000000003' } } } : c));
  }
  // And in readFeedState's (index-probe), its reply's index headers kept.
  for (const s of out.filter((r) => r.row === 'swarm.feed:read')) {
    s.calls = s.calls.map((c, k) => {
      if (c.form !== 'feed_latest') return c;
      const reply = { status: c.reply.status };
      if (reply.status >= 200 && reply.status < 300) reply.headers = s.indexHeaders[k];
      return { ...c, form: 'feed_head', headers: mainHeaders([['swarm-only-root-chunk', 'true']]), reply };
    });
    delete s.indexHeaders;
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
    const scenario = { id, row: base.row, from: `honest/${fromId}`, key: base.key, params: base.params, ...(base.parts ? { parts: base.parts } : {}),
      ...(base.ready ? { ready: base.ready } : {}), rule, note };
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
    structuredClone(calls[1])]);
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
  // The longest honest run is 81 reads; an 82nd is past the cap.
  add('updateFeed-82nd-probe', 'update-feed-head-81-reads', 'count', 'an 82nd head-probe read', (calls) => {
    const probes = calls.filter((c) => c.feed);
    if (probes.length !== MAX_PROBE_READS) throw new Error(`update-feed-head-81-reads probes ${probes.length} times`);
    return [...calls.slice(0, calls.indexOf(probes.at(-1)) + 1), structuredClone(probes.at(-1))];
  });
  add('sendPss-128-hex-recipient', 'send-pss-sent', 'query', 'the 128-hex PSS recipient, bee-js\'s form before #1062', (calls) => {
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
  // With a batch the row has no stamps: the /stamps is refused as the first call.
  add('swarm.publish-batch-and-stamps', 'swarm.publish-data-batch-encrypt', 'order', 'a /stamps when the parent named its batch', () => [
    call('stamps', 'GET', '/stamps', { headers: mainHeaders() })]);
  add('swarm.publish-encrypt-not-asked', 'swarm.publish-data-default', 'header', 'swarm-encrypt under swarm.publish without encrypt', (calls) => {
    last(calls).headers.push(['swarm-encrypt', 'true']);
  });
  add('swarm.stamps-write', 'swarm.stamps-list', 'form', 'any write under swarm.stamps', () => [call('chunk_up', 'POST', '/chunks',
    { headers: mainHeaders([['content-type', 'application/octet-stream']]), body: Buffer.alloc(9) })]);
  // swarm.feed's read: feed_head once, and the head probe only after its 404.
  const readProbe = (calls, index) => {
    const [, , owner, topic] = calls[0].path.split('/');
    return call('chunk', 'GET', `/chunks/${feedAddress(env, topic, owner, index)}`, { headers: mainHeaders(), feed: { owner, index } });
  };
  add('swarm.feed-read-whole-latest', 'swarm.feed-read-latest', 'form', 'a whole feed_latest for the read\'s lookup', (calls) => {
    calls[0].form = 'feed_latest';
    calls[0].headers = calls[0].headers.filter(([n]) => n !== 'swarm-only-root-chunk');
  });
  add('swarm.feed-read-probe-after-found', 'swarm.feed-read-latest', 'order', 'a probe chunk after feed_head found the index', (calls) => [...calls, readProbe(calls, 0)]);
  add('swarm.feed-read-probe-after-500', 'swarm.feed-read-node-500', 'order', 'a probe chunk after feed_head\'s 500 (the read throws it)',
    (calls) => [...calls, readProbe(calls, 0)]);
  add('swarm.feed-read-probe-other-index', 'swarm.feed-read-probe', 'value', 'a probe chunk at another index than the probe asks next', (calls) => {
    const probes = calls.filter((c) => c.feed);
    const third = probes[2];
    const wrong = readProbe(calls, third.feed.index + 1);
    return [...calls.slice(0, calls.indexOf(third)), wrong];
  });
  add('swarm.feed-read-second-head', 'swarm.feed-read-latest', 'count', 'a second feed_head', (calls) => [...calls, structuredClone(calls[0])]);
  add('swarm.feed-read-write', 'swarm.feed-read-latest', 'form', 'a soc_up under swarm.feed\'s read', (calls) => {
    const [, , owner] = calls[0].path.split('/');
    return [...calls, call('soc_up', 'POST', `/soc/${owner}/${'ab'.repeat(32)}`, { query: [['sig', 'cd'.repeat(65)]],
      headers: mainHeaders([['content-type', 'application/octet-stream'], ['swarm-postage-batch-id', C.BATCH_A]]), body: Buffer.alloc(48) })];
  });
  return out;
}

async function buildGrammar(env, methods, nodeBodies, dwebVerify, meta) {
  await prepareWalks(env, methods);
  const fromMethods = honestFromMethods(env, methods, nodeBodies);
  const walks = dwebWalks(env, dwebVerify);
  const two = twoPositions(env);
  const leaf = leafWithLargeSpan(env);
  const deep = deepTrees(env);
  const main = await mainRows(env);
  const honest = [...fromMethods, ...walks, ...two.honest, ...leaf.honest, ...deep.honest, ...main];
  const forbidden = [...forbiddenFrom(honest, env), ...two.forbidden, ...leaf.forbidden, ...deep.forbidden];
  const readDataChecked = checkReadDataScenarios(honest, forbidden, dwebVerify);
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
    // 0009's closed set plus busy and stopped (design 0015, shell.swarm_api:
    // `failed`; freedom-cored's swarm/wire.rs reads the same six).
    failed: ['unreachable', 'error', 'aborted', 'too_large', 'busy', 'stopped'],
    rules: ['form', 'order', 'count', 'value', 'header', 'query', 'body', 'ended'],
    forms: FORMS,
    rows: ROWS,
    deviation_requests: DEVIATION_REQUESTS,
    checked,
    scenarios_checked: { readData: readDataChecked },
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
  scenarios: 'honest and forbidden: { id, row, from, key (the page key), params (swarm.json\'s typed form, or main\'s own params, whole, in the wire '
    + 'form swarm.json\'s shell cases use), parts (main\'s own rows: part k\'s bytes, { bytes, base64 }, for a { part: k } in params, as a shell '
    + 'step\'s parts), ready, calls }. '
    + 'A call: form, method, path, query, headers (as main sends them, main_headers included), body ({ bytes, base64 } or { bytes, sha256 }), '
    + 'max_bytes, feed { owner, index }, tree { length, depth }, and reply (status, headers, body { base64 } or body_ref naming the chunk store it comes from, '
    + 'such as dweb-verify.json swarm.chunks). Every call of an honest scenario is admitted in order; a forbidden scenario\'s calls before its last are '
    + 'admitted and its last is refused before any dial with `rule`.',
  scenarios_checked: 'the readData scenarios played against the design\'s admission rules (Values main derives: the root at params.reference, one '
    + 'ranged bytes, and each later chunk an unfetched slot of an occurrence, address, logical length and depth, that an intermediate main returned names, '
    + 'by 0009\'s geometry): honest ones admitted whole, forbidden ones refused at their last call by their rule. A tree whose chunks carry a '
    + 'redundancy level is skipped (its parities aren\'t modelled here): `skipped` names those scenarios.',
  deep_trees: 'readData-one-chunk-at-depths-6-and-7, readData-leaf-at-depth-8-fetched-again, readData-over-full-intermediate and their forbidden '
    + 'alternatives: chains of lone-reference wrappers (one reference, the child\'s span, as Ant writes one), each giving its child its whole length one '
    + 'level deeper, and a root with more references than its length needs, every chunk core-sdk\'s makeContentAddressedChunk. No honest splitter writes '
    + 'them inside readData\'s 5 MiB; a node can serve them.',
};

module.exports = { buildGrammar };
