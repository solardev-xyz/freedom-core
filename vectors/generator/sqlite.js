'use strict';

// Design 0013's SQLite stores (PRF-5g-1): each database's schema as the
// stores reference creates it. Its own src/main/payment-history.js and
// src/main/swarm/publish-history.js are loaded whole and unpatched, each
// over a fresh directory: `getDb()` opens the database as main does (a new
// file, `journal_mode = WAL`, `migrateDatabase`, then the one-shot imports,
// which find nothing, and publish history's orphan sweep, which finds no
// row), and `closeDb()` closes it. Their Electron, logger, Freedom root and
// broadcast requires are stubbed (inert, or the directory); the driver is
// the main reference's better-sqlite3, whose Node-API prebuilds `npm ci
// --ignore-scripts` unpacks with the package (13.x ships them for every
// platform, Node 24 among them), so nothing is built. The closed file is
// then read back: `sqlite_master`'s rows in the order SQLite wrote them,
// `user_version` and `journal_mode`.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createRequire } = require('node:module');
const { loadWithInternals } = require('./naming');
const { buildPayments } = require('./sqlite-payments');

const DATABASES = [
  { file: 'payment-history.sqlite', module: 'src/main/payment-history.js', prefix: '.' },
  { file: 'publish-history.sqlite', module: 'src/main/swarm/publish-history.js', prefix: '..' },
];

const SILENT_LOG = { info() {}, warn() {}, error() {}, debug() {} };

function schemaOf(checkout, Database, { file, module, prefix }) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freedom-core-sqlite-'));
  try {
    const inert = () => {};
    const electron = {
      app: { getPath: (name) => { assert.equal(name, 'userData'); return directory; } },
      ipcMain: { handle: inert, on: inert, removeHandler: inert },
    };
    const reference = loadWithInternals(checkout, module, [], {
      electron,
      'better-sqlite3': Database,
      [`${prefix}/logger`]: SILENT_LOG,
      [`${prefix}/freedom-root`]: { getFreedomDataPath: (name) => path.join(directory, name) },
      './lib/broadcast-to-all-webcontents': { broadcastToAllWebContents: inert },
    });
    reference.getDb();
    reference.closeDb();
    assert.deepEqual(fs.readdirSync(directory).filter((name) => !name.startsWith(file)), [],
      `${module} wrote only its database`);
    const db = new Database(path.join(directory, file), { readonly: true, fileMustExist: true });
    try {
      return {
        file,
        module,
        user_version: db.pragma('user_version', { simple: true }),
        journal_mode: db.pragma('journal_mode', { simple: true }),
        sqlite_master: db.prepare('SELECT type, name, tbl_name, rootpage, sql FROM sqlite_master ORDER BY rowid').all()
          .map((row) => ({ ...row })),
      };
    } finally {
      db.close();
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

/** `sqlite.json`: `checkout` is the stores reference, `driverCheckout` the
 * main reference, whose installed better-sqlite3 runs both modules. */
function buildSqlite(checkout, driverCheckout, meta) {
  const Database = createRequire(path.join(driverCheckout, 'package.json'))('better-sqlite3');
  const probe = new Database(':memory:');
  const sqliteVersion = probe.prepare('SELECT sqlite_version() AS version').get().version;
  probe.close();
  return {
    meta: { ...meta, sqliteVersion },
    description: 'Design 0013\'s SQLite stores (PRF-5g-1): each database as the stores reference\'s own module creates it '
      + 'through better-sqlite3 (getDb on a new file, then closeDb), read back: sqlite_master\'s rows in rowid order '
      + '(type, name, tbl_name, rootpage, sql), user_version and journal_mode. The core creates each with the same DDL '
      + 'and must read back the same rows. `payments` (PRF-5g-2, sqlite-payments.js): payment-history.js\'s operations on one '
      + 'database and its legacy x402-receipts.json imports, each step\'s result (its answer, or the error it threw) and the '
      + 'table after it where it changed (each column as [typeof, value], an INTEGER as its decimal text).',
    databases: DATABASES.map((database) => schemaOf(checkout, Database, database)),
    payments: buildPayments(checkout, Database),
  };
}

module.exports = { buildSqlite };
