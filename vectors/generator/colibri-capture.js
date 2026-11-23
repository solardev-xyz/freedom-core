'use strict';

// Captures vectors/fixtures/colibri/ once from the live servers, as
// freedom-browser's docs/audits/evidence/colibri-v3-2026-09/capture.cjs
// captures checkpoints: every case of colibri-cases.js runs through the same
// harness as the generator (colibri.js), with the reference unchanged, but a
// fetch its rules and its session's earlier captures don't answer goes to
// the network. Each such request is recorded (URL, method, headers, body,
// any redirect the server gave) with its answer (status, content type, and
// the body, stored by its SHA-256), and so is each case's clock. A session
// answers a request it has seen again from its capture, so its cases share
// one world. Run it only to replace the fixtures, from a clean colibri
// reference, and review the diff:
//
//   node vectors/generator/colibri-capture.js --colibri-browser <checkout> [--session <id>...]
//
// It needs the network; the generator never does.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const colibri = require('./colibri');

const REDIRECTS = [301, 302, 303, 307, 308];
// Node's own fetch, kept before the harness stubs globalThis.fetch per case.
const realFetch = globalThis.fetch;

async function liveFetch(dir, { url, method, headers, body }) {
  const redirects = [];
  let target = url;
  let verb = method;
  for (let hop = 0; hop <= 5; hop += 1) {
    let response;
    try {
      response = await realFetch(target, { method: verb, headers, body: verb === 'GET' ? undefined : body ?? undefined,
        redirect: 'manual', signal: AbortSignal.timeout(60000) });
    } catch (error) {
      return { url, method, headers, body, ...(redirects.length ? { redirects } : {}), response: { error: error.message } };
    }
    const location = response.headers.get('location');
    if (REDIRECTS.includes(response.status) && location) {
      redirects.push({ status: response.status, location });
      target = new URL(location, target).href;
      if (response.status === 303) verb = 'GET';
      continue;
    }
    const bytes = Buffer.from(await response.arrayBuffer());
    const sha = colibri.sha256(bytes);
    fs.mkdirSync(path.join(dir, 'bodies'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'bodies', `${sha}.bin`), bytes);
    const type = response.headers.get('content-type');
    return { url, method, headers, body, ...(redirects.length ? { redirects } : {}),
      response: { status: response.status, ...(type ? { content_type: type } : {}), bytes: bytes.length, sha256: sha } };
  }
  throw new Error(`Too many redirects: ${url}`);
}

async function main() {
  const args = process.argv.slice(2);
  assert.ok(args[0] === '--colibri-browser' && args[1], 'Usage: node vectors/generator/colibri-capture.js --colibri-browser <checkout> [--session <id>...]');
  const reference = colibri.loadColibriReference(path.resolve(args[1]));
  const only = new Set();
  for (let i = 2; i < args.length; i += 2) {
    assert.equal(args[i], '--session');
    only.add(args[i + 1]);
  }
  const dir = colibri.FIXTURES;
  fs.mkdirSync(path.join(dir, 'bodies'), { recursive: true });
  const fixtures = colibri.loadFixtures(dir);
  const { CASES } = require('./colibri-cases');
  const sessions = [...new Set(CASES.filter((kase) => kase.kind !== 'checkpoint').map((kase) => kase.session))]
    .filter((id) => only.size === 0 || only.has(id));
  for (const id of sessions) {
    const exchanges = [];
    // The real clock, kept before the harness fixes Date.now per case.
    const realNow = Date.now;
    const live = {
      dir,
      pool: new Map(),
      inflight: new Map(),
      params: {},
      clocks: {},
      now: () => realNow(),
      // Out of band, for a case's inputs only: the package's first RPC host.
      rpc: async (chain, method, params) => {
        const response = await realFetch(reference.servers[chain].eth_rpc[0], { method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(30000) });
        return (await response.json()).result;
      },
      fetch: async (request) => {
        const exchange = await liveFetch(dir, request);
        exchanges.push(exchange);
        return exchange;
      },
    };
    const stores = new Map();
    const cases = CASES.filter((kase) => kase.session === id);
    for (const kase of cases) {
      // Store seeds from another session are the generator's own runs.
      const run = await colibri.runCase(reference, kase, { session: null, stores, live });
      live.clocks[kase.id] = run.clocks;
      if (run.outcome.store) stores.set(kase.id, run.outcome.store);
      const last = run.outcome.outcomes.at(-1);
      console.log(`${id} ${kase.id}: ${last.ok ? 'ok' : `error ${JSON.stringify(last.error?.message ?? last).slice(0, 160)}`}`);
    }
    fixtures.sessions[id] = { chain: cases[0].chain, captured_at: new Date(realNow()).toISOString(), params: live.params, clocks: live.clocks, exchanges };
  }
  // The checkpoint cases' proofs, freedom-browser's own captures, copied so a
  // replay outside the browser has them; the generator checks the copies.
  const proofs = new Set();
  for (const kase of CASES.filter((candidate) => candidate.kind === 'checkpoint')) {
    for (const proof of kase.capture(reference).proofs) {
      const sha = colibri.sha256(proof);
      fs.writeFileSync(path.join(dir, 'bodies', `${sha}.bin`), proof);
      proofs.add(sha);
    }
  }
  fixtures.checkpoint_proofs = [...proofs].sort();
  fixtures.meta = {
    colibriBrowserCommit: require('node:child_process').execFileSync('git', ['rev-parse', 'HEAD'], { cwd: reference.checkout, encoding: 'utf8' }).trim(),
    colibriVersion: colibri.COLIBRI_VERSION,
    nodeVersion: process.version,
    capture: 'vectors/generator/colibri-capture.js',
  };
  // Bodies no session names any more are dropped.
  const named = new Set(Object.values(fixtures.sessions).flatMap((session) => session.exchanges.map((exchange) => exchange.response.sha256).filter(Boolean)));
  for (const file of fs.readdirSync(path.join(dir, 'bodies'))) {
    if (file.endsWith('.bin') && !named.has(file.slice(0, -4)) && !fixtures.checkpoint_proofs?.includes(file.slice(0, -4))) {
      fs.rmSync(path.join(dir, 'bodies', file));
    }
  }
  fs.writeFileSync(path.join(dir, 'sessions.json'), JSON.stringify(fixtures, null, 2) + '\n');
}

main().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
