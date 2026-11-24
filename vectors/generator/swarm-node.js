'use strict';

// The recording fake Swarm node for vectors/swarm.json (design 0015, SWM-1).
//
// A real HTTP server on loopback, so the reference's own transports reach it
// unchanged: bee-js and main's own calls over global fetch (undici), and
// page-upload.js over Node's `http`. Two thin wrappers, one around global
// fetch and one around `http.request`, note the headers the caller set
// (never the transport's own) and tag each request with a sequence number,
// which the server takes off again; the server records the method, path,
// query and the body bytes as they arrived. Global WebSocket is a fake that
// records the URL it was opened for.
//
// What the node answers is the case's script: a list of rules tried in
// order (`{ match, reply, times }`), then the node's own behaviour over the
// chunks, blobs and feeds the case gave it, computed with the reference's
// own core-sdk (content addresses, SOC addresses, chunk trees). Nothing the
// reference is tested on is computed here: the node only stores and serves.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');

const SEQ_HEADER = 'x-swarm-vector-seq';
// Header names the transports add on their own, never a caller's.
const TRANSPORT_HEADERS = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'keep-alive',
  'user-agent', 'accept-language', 'sec-fetch-mode', SEQ_HEADER]);
// The node's URL in every recorded text: the harness's own port is replaced.
const NODE_URL = 'http://127.0.0.1:1633';

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const hex = (bytes) => Buffer.from(bytes).toString('hex');

/** A headers value as fetch or http.request take it, as `[name, value]` pairs in order, names lower-cased. */
function headerPairs(headers) {
  if (!headers) return [];
  if (typeof headers.entries === 'function' && !Array.isArray(headers)) {
    return [...headers.entries()].map(([name, value]) => [name.toLowerCase(), String(value)]);
  }
  if (Array.isArray(headers)) return headers.map(([name, value]) => [String(name).toLowerCase(), String(value)]);
  return Object.entries(headers).map(([name, value]) => [name.toLowerCase(), String(value)]);
}

/** `fn` with `globalThis.Date` reading `clock.now` for `new Date()` and `Date.now()`. */
function fixedDate(clock) {
  const RealDate = globalThis.Date;
  class FixedDate extends RealDate {
    constructor(...args) {
      if (args.length === 0) super(clock.now);
      else super(...args);
    }
    static now() {
      return clock.now;
    }
  }
  return { RealDate, FixedDate };
}

/**
 * The node. `core` is the reference's core-sdk. `world`:
 * - `rules`: `[{ match: { method?, path?, prefix? }, reply, times? }]`, tried first;
 * - `chunks`: address → the bytes the node stores (span ‖ payload, or a SOC);
 * - `blobs`: root address → the bytes `/bytes` joins;
 * - `feeds`: `[{ owner, topic, latest }]`: `latest` is GET /feeds' answer;
 * - `stamps`, `addresses`, `tags`, `node`: JSON answers.
 * Uploads are stored as a node would: `/chunks` and `/soc` by their address,
 * `/bytes` with every chunk of its tree.
 */
class FakeNode {
  constructor(core, world = {}, trees = new Map()) {
    this.core = core;
    this.trees = trees;
    this.rules = (world.rules || []).map((rule) => ({ ...rule, left: rule.times ?? Infinity }));
    this.chunks = new Map(Object.entries(world.chunks || {}));
    this.blobs = new Map(Object.entries(world.blobs || {}));
    this.feeds = world.feeds || [];
    this.stamps = world.stamps;
    this.addresses = world.addresses;
    this.tags = world.tags || {};
    this.nodeInfo = world.node || { beeMode: 'light', chequebookEnabled: true, swapEnabled: true };
    // address → { owner, index }: the feed updates the case's probes may ask for.
    this.feedIndex = new Map(Object.entries(world.feedIndex || {}));
    this.requests = [];
    this.client = new Map();
    this.seq = 0;
    this.sockets = new Set();
    this.websockets = [];
    this.bzzTag = 101;
  }

  async start() {
    this.server = http.createServer((req, res) => this.handle(req, res));
    this.server.on('connection', (socket) => {
      this.sockets.add(socket);
      socket.on('close', () => this.sockets.delete(socket));
    });
    await new Promise((resolve) => this.server.listen(0, '127.0.0.1', resolve));
    this.port = this.server.address().port;
    this.url = `http://127.0.0.1:${this.port}`;
    return this.url;
  }

  async stop() {
    for (const socket of this.sockets) socket.destroy();
    await new Promise((resolve) => this.server.close(resolve));
  }

  /** `text` with the harness's port replaced by the node's fixed URL. */
  normalize(text) {
    if (typeof text !== 'string' || !this.port) return text;
    return text.split(`127.0.0.1:${this.port}`).join(NODE_URL.slice('http://'.length));
  }

  /** The caller's side of a request: its headers as set, by sequence number. */
  noteClient(via, method, url, headers) {
    this.seq += 1;
    const pairs = headerPairs(headers).filter(([name]) => !TRANSPORT_HEADERS.has(name));
    this.client.set(this.seq, { via, method, headers: pairs, url: String(url) });
    return this.seq;
  }

  /** Installs the fetch, http.request and WebSocket wrappers; returns their undo. */
  install() {
    const node = this;
    const realFetch = globalThis.fetch;
    const realRequest = http.request;
    const realWebSocket = globalThis.WebSocket;
    globalThis.fetch = function fetch(input, init = {}) {
      const url = typeof input === 'string' || input instanceof URL ? String(input) : input.url;
      const method = (init.method || 'GET').toUpperCase();
      const seq = node.noteClient('fetch', method, url, init.headers);
      const headers = [...headerPairs(init.headers), [SEQ_HEADER, String(seq)]];
      return realFetch(url, { ...init, headers });
    };
    http.request = function request(url, options, callback) {
      assert.ok(typeof options === 'object' && options !== null, 'page-upload passes (url, options, callback)');
      const seq = node.noteClient('http', (options.method || 'GET').toUpperCase(), url, options.headers);
      return realRequest.call(http, url, { ...options, headers: { ...options.headers, [SEQ_HEADER]: String(seq) } }, callback);
    };
    globalThis.WebSocket = class FakeWebSocket {
      constructor(url) {
        this.url = url;
        this.readyState = 0;
        node.websockets.push(node.normalize(String(url)));
        setImmediate(() => {
          this.readyState = 1;
          this.onopen?.({});
        });
      }
      close() {
        this.readyState = 3;
      }
    };
    return () => {
      globalThis.fetch = realFetch;
      http.request = realRequest;
      globalThis.WebSocket = realWebSocket;
    };
  }

  handle(req, res) {
    const parts = [];
    req.on('data', (part) => parts.push(part));
    req.on('error', () => {});
    req.on('end', async () => {
      const body = Buffer.concat(parts);
      const seq = Number(req.headers[SEQ_HEADER]);
      const client = this.client.get(seq);
      assert.ok(client, `a request reached the fake node without passing a wrapper: ${req.method} ${req.url}`);
      const url = new URL(req.url, this.url);
      const request = {
        seq,
        via: client.via,
        method: req.method,
        path: url.pathname,
        query: [...url.searchParams.entries()],
        headers: client.headers,
        body,
      };
      this.requests.push(request);
      let reply;
      try {
        reply = await this.answer(request);
      } catch (err) {
        reply = { status: 599, statusText: 'Fake node failed', json: { message: String(err.stack || err) } };
      }
      this.send(res, reply, request);
    });
  }

  send(res, reply, request) {
    // The page gives up (its timer, its document gone) as this request
    // arrives: its signal aborts, and the reply, if any, comes after.
    if (reply.abortPage) {
      this.abortPage?.();
      const { abortPage, ...rest } = reply;
      reply = rest;
    }
    if (reply.delayMs) {
      const { delayMs, ...rest } = reply;
      setTimeout(() => this.send(res, rest, request), delayMs).unref?.();
      return;
    }
    request.reply = { status: reply.status };
    if (reply.hangUp) {
      res.socket.destroy();
      return;
    }
    let body = reply.body ?? Buffer.alloc(0);
    if (reply.json !== undefined) body = Buffer.from(JSON.stringify(reply.json));
    if (typeof body === 'string') body = Buffer.from(body, 'utf8');
    const headers = { ...(reply.headers || {}) };
    if (reply.json !== undefined && !headers['content-type']) headers['content-type'] = 'application/json; charset=utf-8';
    if (reply.chunked) {
      request.replyBody = Buffer.concat(reply.pieces || [body]);
      request.replyHeaders = headers;
      res.writeHead(reply.status, reply.statusText || http.STATUS_CODES[reply.status] || '', headers);
      for (const piece of reply.pieces || [body]) res.write(piece);
      if (reply.cutAfterPieces) {
        res.socket.destroy();
        return;
      }
      res.end();
      return;
    }
    request.replyBody = body;
    request.replyHeaders = headers;
    headers['content-length'] = String(reply.declare ?? body.length);
    res.writeHead(reply.status, reply.statusText ?? (http.STATUS_CODES[reply.status] || ''), headers);
    if (reply.declare !== undefined && reply.declare > body.length) {
      res.write(body);
      res.socket.destroy();
      return;
    }
    res.end(body);
  }

  async answer(request) {
    for (const rule of this.rules) {
      if (rule.left <= 0 || !matches(rule.match, request)) continue;
      rule.left -= 1;
      return typeof rule.reply === 'function' ? rule.reply(request, this) : rule.reply;
    }
    return this.own(request);
  }

  /** The node's own answers, over what it stores. */
  async own(request) {
    const { core } = this;
    const { method, path } = request;
    const notFound = { status: 404, statusText: 'Not Found', json: { code: 404, message: 'Not Found' } };
    if (method === 'GET' && path === '/node') return { status: 200, json: this.nodeInfo };
    if (method === 'GET' && path === '/stamps') return { status: 200, json: this.stamps ?? { stamps: [] } };
    if (method === 'GET' && path === '/addresses' && this.addresses) return { status: 200, json: this.addresses };
    if (method === 'GET' && path.startsWith('/tags/')) {
      const tag = this.tags[path.slice('/tags/'.length)];
      return tag ? { status: 200, json: tag } : notFound;
    }
    if (method === 'GET' && path.startsWith('/chunks/')) {
      const chunk = this.chunks.get(path.slice('/chunks/'.length));
      return chunk ? { status: 200, headers: { 'content-type': 'binary/octet-stream' }, body: chunk } : notFound;
    }
    if (method === 'GET' && path.startsWith('/bytes/')) {
      const blob = this.blobs.get(path.slice('/bytes/'.length));
      return blob ? { status: 200, headers: { 'content-type': 'application/octet-stream' }, body: blob } : notFound;
    }
    if (method === 'GET' && path.startsWith('/feeds/')) {
      const [, , owner, topic] = path.split('/');
      const feed = this.feeds.find((f) => f.owner === owner && f.topic === topic);
      return feed?.latest ?? notFound;
    }
    if (method === 'POST' && path === '/chunks') {
      const span = request.body.subarray(0, 8);
      const payload = request.body.subarray(8);
      const address = core.makeContentAddressedChunk(payload, span.readBigUInt64LE(0)).address.toHex();
      this.chunks.set(address, request.body);
      return { status: 201, headers: { 'swarm-tag': '0' }, json: { reference: address } };
    }
    if (method === 'POST' && path.startsWith('/soc/')) {
      const [, , owner, identifier] = path.split('/');
      const signature = new URLSearchParams(request.query).get('sig');
      const address = core.makeSOCAddress(new core.Identifier(identifier), new core.EthAddress(owner)).toHex();
      this.chunks.set(address, Buffer.concat([Buffer.from(identifier, 'hex'), Buffer.from(signature, 'hex'), request.body]));
      return { status: 201, json: { reference: address } };
    }
    if (method === 'POST' && path === '/bytes') {
      const key = sha256(request.body);
      if (!this.trees.has(key)) this.trees.set(key, await splitTree(core, request.body));
      const tree = this.trees.get(key);
      for (const chunk of tree.chunks) this.chunks.set(chunk.address, chunk.wire);
      this.blobs.set(tree.root.address, Buffer.from(request.body));
      return { status: 201, headers: { 'swarm-tag': String(this.bzzTag++) }, json: { reference: tree.root.address } };
    }
    if (method === 'POST' && path === '/bzz') {
      // The node builds the manifest; its reference is the node's word. This
      // node's: SHA-256 of the body.
      return { status: 201, headers: { 'swarm-tag': String(this.bzzTag++) }, json: { reference: sha256(request.body) } };
    }
    if (method === 'POST' && path.startsWith('/feeds/')) {
      return { status: 201, json: { reference: sha256(Buffer.from(`feed manifest ${path}`)) } };
    }
    if (method === 'POST' && path.startsWith('/pss/send/')) return { status: 201, body: Buffer.alloc(0) };
    return { status: 500, statusText: 'Internal Server Error', json: { code: 500, message: `fake node: no answer for ${method} ${path}` } };
  }
}

function matches(match, request) {
  if (match.method && match.method !== request.method) return false;
  if (match.path && match.path !== request.path) return false;
  if (match.prefix && !request.path.startsWith(match.prefix)) return false;
  return true;
}

/**
 * The chunk tree of `data` as core-sdk's ChunkSplitter builds it, each chunk
 * as a node stores it (span ‖ unpadded payload): the reference's own tree.
 */
async function splitTree(core, data, piece = 4096) {
  const chunks = [];
  const wire = (chunk) => {
    const span = Buffer.alloc(8);
    span.writeBigUInt64LE(chunk.span);
    const payload = Buffer.from(chunk.writer.buffer.subarray(0, chunk.writer.cursor));
    return { address: chunk.hash().toHex(), span: chunk.span, payload, wire: Buffer.concat([span, payload]) };
  };
  const splitter = new core.ChunkSplitter(async (batch) => {
    for (const { chunk } of batch) chunks.push(wire(chunk));
    return [];
  });
  for (let offset = 0; offset < data.length; offset += piece) {
    await splitter.append(data.subarray(offset, Math.min(data.length, offset + piece)));
  }
  if (data.length === 0) await splitter.append(data);
  const root = wire(await splitter.finalize());
  return { root, chunks: [...chunks, root] };
}

module.exports = { FakeNode, splitTree, fixedDate, headerPairs, sha256, hex, NODE_URL, SEQ_HEADER };
