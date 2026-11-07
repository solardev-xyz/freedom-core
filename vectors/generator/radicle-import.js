'use strict';

// Design 0008's import (step 4, item 15; design 0010, D5): what main sends
// for an import, and how it reads the answers and the errors. The
// reference's own github-bridge.js runs whole (its `importGitHubRepo`, the
// one caller of `importRepo` in main), over the reference's own
// radicle-embedded.js and a scripted add-on, through naming.js's harness:
// their own requires are stubbed, and no reference code is copied. `git`,
// GitHub's API, the network check and the profile's temporary directory are
// scripted; each case loads the modules afresh, so no bridge map carries
// over.
//
// What only the service has is the design's (`source: design`): its answer
// to each case, `{ rid }` or an error with its code and message (0008,
// "Methods" and "Errors"; 0010, D5). Each error case hands the service's
// message to main as the add-on's `{"error": …}` would, and records what
// main makes of it; the generator checks that none of the service's
// messages but "already exists" trips one of main's readings.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const util = require('node:util');
const { EventEmitter } = require('node:events');
const { isDeepStrictEqual } = require('node:util');
const { loadWithInternals } = require('./naming');

// Where the reference looks for the add-on (radicle-reads.js).
const ADDON = '/freedom-core-vectors/libradicle.node';
const RID = 'rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5';
/** What the scripted `createProfileTempDir('github-bridge')` returns. */
const TEMP = '/profile/tmp/github-bridge-AbC123';
const RADICLE_HOME = '/profile/radicle-data';

const text = (value) => JSON.stringify(value);

/** libradicle's `json::rid`: `{"rid": "<rid>"}`, the add-on's answer, and
 * the service's result. */
const ridText = (rid) => text({ rid });

// ---- main at the reference ----------------------------------------------

function loadBridge(checkout, world) {
  const answer = (name, args) => {
    world.calls.push({ export: name, args });
    const found = world.script.find((e) => e.export === name && isDeepStrictEqual(e.args, args) && !e.used);
    if (!found) {
      world.unscripted.push({ export: name, args });
      return text({ error: `unscripted ${name}` });
    }
    found.used = true;
    return found.text;
  };
  const addon = new Proxy({}, { get: (_, name) => (typeof name === 'string' ? (...args) => answer(name, args) : undefined) });
  const log = { debug() {}, error() {}, log() {}, info() {}, warn() {} };
  const embedded = loadWithInternals(checkout, 'src/main/radicle-embedded.js', [], {
    './logger': log,
    fs: { ...fs, existsSync: (p) => p === ADDON || fs.existsSync(p) },
    [ADDON]: addon,
  });
  // `execFileAsync = promisify(execFile)`: the scripted git, in order.
  const execFile = () => { throw new Error('the callback form of execFile is not used'); };
  execFile[util.promisify.custom] = async (file, args, options) => {
    world.git.push({ file, args, cwd: options?.cwd ?? null, timeout: options?.timeout ?? null });
    const step = world.gitScript.shift();
    assert.ok(step && step.command === args[0], `unscripted git ${args.join(' ')}`);
    if (step.error) throw Object.assign(new Error(step.error), { stderr: step.stderr ?? '' });
    return { stdout: step.stdout ?? '', stderr: '' };
  };
  const https = {
    // The network check: GitHub answers 200.
    request: (url, options, callback) => {
      world.https.push({ method: options.method, url });
      const req = new EventEmitter();
      req.end = () => setImmediate(() => callback({ statusCode: 200, resume() {} }));
      req.destroy = () => {};
      return req;
    },
    // The description: the scripted body.
    get: (url, options, callback) => {
      world.https.push({ method: 'GET', url });
      const req = new EventEmitter();
      req.destroy = () => {};
      setImmediate(() => {
        const res = new EventEmitter();
        callback(res);
        res.emit('data', world.description);
        res.emit('end');
      });
      return req;
    },
  };
  return loadWithInternals(checkout, 'src/main/github-bridge.js', ['importGitHubRepo'], {
    electron: { ipcMain: { handle() {} } },
    child_process: { execFile },
    https,
    fs: {
      ...fs,
      existsSync: () => false,
      writeFileSync: (p, data) => world.writes.push({ path: p, data: String(data) }),
    },
    './radicle-manager': {
      getCurrentStatus: () => ({ status: 'running' }),
      isDisabledForProfile: () => false,
      STATUS: { RUNNING: 'running' },
    },
    './radicle-embedded': embedded,
    './profile-paths': {
      createProfileTempDir: (prefix) => { world.temp.push(prefix); return TEMP; },
      prepareRadicleDataDir: async () => RADICLE_HOME,
    },
    './fs-offload': { removePath: async (p) => { world.removed.push(p); } },
  });
}

/** Runs `importGitHubRepo(c.url)` with `c`'s script, and records what main
 * did. */
async function runCase(checkout, c) {
  const world = {
    script: [{ export: 'importRepo', args: c.args, text: c.answer }],
    gitScript: [
      { command: '--version', stdout: 'git version 2.43.0\n' },
      { command: 'clone' },
      c.branch === null ? { command: 'symbolic-ref', error: 'fatal: ref HEAD is not a symbolic ref' } : { command: 'symbolic-ref', stdout: `${c.branch}\n` },
    ],
    description: c.description,
    calls: [], unscripted: [], git: [], https: [], temp: [], writes: [], removed: [], progress: [], console: [],
  };
  const bridge = loadBridge(checkout, world).__internals;
  const sender = { isDestroyed: () => false, send: (channel, data) => world.progress.push({ channel, data }) };
  const saved = { log: console.log, warn: console.warn, error: console.error };
  for (const level of Object.keys(saved)) {
    console[level] = (...parts) => world.console.push({ level, line: parts.map(String).join(' ') });
  }
  let result;
  try {
    result = await bridge.importGitHubRepo(c.url, sender);
  } finally {
    Object.assign(console, saved);
  }
  assert.deepEqual(world.unscripted, [], `${c.id}: unscripted add-on calls`);
  assert.ok(world.script.every((e) => e.used), `${c.id}: importRepo never called`);
  assert.equal(world.gitScript.length, 0, `${c.id}: git steps left`);
  return {
    result,
    calls: world.calls,
    git: world.git,
    https: world.https,
    temp: world.temp,
    progress: world.progress,
    writes: world.writes,
    removed: world.removed,
    console: world.console,
  };
}

// ---- the cases ----------------------------------------------------------

const BROWSER = 'https://github.com/solardev-xyz/freedom-browser';

/** A case importing `url`, whose clone lands in `TEMP/<repo>`. */
function bridged(id, url, repo, { branch = 'main', description = text({ description: 'A browser.' }), answer, service, expectedDescription }) {
  return {
    id,
    url,
    branch,
    description,
    args: [`${TEMP}/${repo}`, repo, expectedDescription ?? JSON.parse(description).description, branch ?? 'main'],
    answer,
    service,
  };
}

/** The service's errors before or past the start (0008, "Errors"; 0010,
 * D5), as `source: design`: each code and message, which main at the
 * reference reads as the add-on's error text. */
const SERVICE_ERRORS = [
  { id: 'exists', code: 'failed', message: `${RID} already exists in storage` },
  { id: 'outcome-unknown', code: 'outcome_unknown', message: 'the import was cut off past its start: it may have been recorded' },
  { id: 'needs-vault', code: 'needs_vault', message: 'the node runs with a throwaway key: publishing needs a vault' },
  { id: 'unsupported-layout', code: 'unsupported_layout', message: "the repository is, contains, or lies inside a directory of Freedom's own" },
  { id: 'no-branch', code: 'invalid_argument', message: 'the working copy has no branch main' },
  { id: 'params', code: 'invalid_argument', message: 'rad.import_repo takes { path, name, description, default_branch }' },
  { id: 'path', code: 'invalid_argument', message: "path isn't the --source this import process was started with" },
  { id: 'already-called', code: 'invalid_argument', message: 'rad.import_repo was already called' },
  { id: 'before-reconcile', code: 'stopped', message: 'rad.import_repo is admitted only after rad.reconcile has succeeded' },
  { id: 'ending', code: 'stopped', message: 'the import process is ending' },
  // libgit2's own text for a directory that isn't a repository: the
  // service answers it as today's message test reads it.
  { id: 'not-a-repository', code: 'not_found', message: `could not find repository at '${TEMP}/freedom-browser'; class=Repository (6); code=NotFound (-3)` },
];

function cases() {
  const out = [
    bridged('imported', BROWSER, 'freedom-browser', { answer: ridText(RID), service: { result_text: ridText(RID) } }),
    bridged('imported-no-description', `${BROWSER}.git`, 'freedom-browser', {
      description: text({}),
      expectedDescription: 'Imported from github.com/solardev-xyz/freedom-browser',
      answer: ridText(RID),
      service: { result_text: ridText(RID) },
    }),
    bridged('imported-trunk', 'octo/hello', 'hello', { branch: 'trunk', answer: ridText(RID), service: { result_text: ridText(RID) } }),
    bridged('imported-default-branch-unknown', 'github.com/octo/hello', 'hello', {
      branch: null,
      answer: ridText(RID),
      service: { result_text: ridText(RID) },
    }),
    // Main's own check of what it got back.
    bridged('invalid-rid', BROWSER, 'freedom-browser', { answer: ridText('not-a-radicle-id') }),
  ];
  for (const e of SERVICE_ERRORS) {
    out.push(bridged(`error-${e.id}`, BROWSER, 'freedom-browser', {
      answer: text({ error: e.message }),
      service: { error: { code: e.code, message: e.message } },
    }));
  }
  return out;
}

async function buildRadicleImport(checkout, meta) {
  const previous = process.env.FREEDOM_RADICLE_ADDON;
  process.env.FREEDOM_RADICLE_ADDON = ADDON;
  try {
    const imports = [];
    for (const c of cases()) {
      const main = await runCase(checkout, c);
      const entry = { id: c.id, url: c.url, default_branch: c.branch, description_body: c.description };
      entry.addon = { args: c.args, text: c.answer };
      if (c.service) entry.expect = { source: 'design', ...c.service };
      entry.main = main;
      imports.push(entry);
    }
    // What main sends: the clone's path, the repository's name, the
    // description and the default branch, in that order.
    for (const e of imports) assert.deepEqual(e.main.calls, [{ export: 'importRepo', args: e.addon.args }], e.id);
    // Main reads `{ rid }` as the service writes it.
    for (const e of imports.filter((x) => x.expect?.result_text)) {
      assert.equal(e.main.result.success, true, e.id);
      assert.equal(e.main.result.rid, RID.slice(4), e.id);
    }
    // No message of the service's trips one of main's readings, but the
    // one that names an existing repository.
    for (const e of imports.filter((x) => x.expect?.error)) {
      const { code, message } = e.main.result.error;
      if (e.id === 'error-exists') {
        assert.equal(code, 'ALREADY_BRIDGED', e.id);
        assert.deepEqual(e.main.result.error.details, { rid: RID.slice(4) }, e.id);
      } else {
        assert.equal(code, 'IMPORT_FAILED', e.id);
        assert.equal(message, e.expect.error.message, e.id);
      }
    }
    return {
      meta,
      formats: {
        imports: '`importGitHubRepo(url)` at the reference, whole: `default_branch` is what the scripted `git symbolic-ref --short HEAD` prints (null: it fails), `description_body` the scripted GitHub API body; `addon` the one `importRepo` call main makes (its arguments: the clone\'s path, the repository\'s name, the description and the default branch, which `rad.import_repo` takes as `path`, `name`, `description` and `default_branch`) and the add-on\'s answer text; `main` what main then did: its result, the add-on calls, the git commands, the HTTPS requests, the temporary directory\'s prefix, the progress it sent, the bridge map it wrote, the directories it removed and its console lines. `expect` (`source: design`) is the service\'s answer: `result_text`, libradicle\'s `json::rid` text, or `error` with its code and message, whose message is the text main reads.',
      },
      constants: { rid: RID, temp: TEMP, radicle_home: RADICLE_HOME },
      imports,
    };
  } finally {
    if (previous === undefined) delete process.env.FREEDOM_RADICLE_ADDON;
    else process.env.FREEDOM_RADICLE_ADDON = previous;
  }
}

module.exports = { buildRadicleImport, SERVICE_ERRORS };
