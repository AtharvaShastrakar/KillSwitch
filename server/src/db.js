import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

export function openDb(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(path.join(dataDir, 'killswitch.db'));
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      pw_hash TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      admin_id INTEGER NOT NULL REFERENCES admins(id),
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS employees (
      id INTEGER PRIMARY KEY,
      emp_code TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      email TEXT,
      status TEXT NOT NULL DEFAULT 'ACTIVE',      -- ACTIVE | OFFBOARDING | LEFT
      last_day INTEGER,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY,
      serial TEXT UNIQUE NOT NULL,
      hostname TEXT,
      os TEXT,
      employee_id INTEGER REFERENCES employees(id),
      state TEXT NOT NULL DEFAULT 'ACTIVE',
      token_hash TEXT,
      enrolled_at INTEGER,
      last_seen INTEGER,
      lease_expires INTEGER,
      recovery_key_enc TEXT,
      state_changed_at INTEGER,
      grace_ends_at INTEGER,
      wipe_due_at INTEGER,
      lock_confirmed_at INTEGER,
      agent_version TEXT,
      last_report TEXT
    );
    CREATE TABLE IF NOT EXISTS commands (
      id TEXT PRIMARY KEY,
      device_id INTEGER NOT NULL REFERENCES devices(id),
      action TEXT NOT NULL,                       -- lock | unlock | wipe
      status TEXT NOT NULL,                       -- queued | sent | done | failed | cancelled
      created_at INTEGER NOT NULL,
      sent_at INTEGER,
      acked_at INTEGER,
      result TEXT
    );
    CREATE TABLE IF NOT EXISTS wipe_approvals (
      device_id INTEGER NOT NULL REFERENCES devices(id),
      admin_id INTEGER NOT NULL REFERENCES admins(id),
      created_at INTEGER NOT NULL,
      PRIMARY KEY (device_id, admin_id)
    );
    CREATE TABLE IF NOT EXISTS enroll_tokens (
      token_hash TEXT PRIMARY KEY,
      created_by INTEGER,
      expires_at INTEGER NOT NULL,
      uses_left INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY,
      ts INTEGER NOT NULL,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,
      device_id INTEGER,
      employee_id INTEGER,
      details TEXT
    );

    -- The audit log is append-only: block edits and deletes at the database level.
    CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
      BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
      BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
  `);
  // Migrations for databases created by older versions.
  const cols = db.prepare('PRAGMA table_info(devices)').all().map((c) => c.name);
  for (const [col, type] of [['recovery_key_id', 'TEXT'], ['reported_key_id', 'TEXT'], ['reenroll_until', 'INTEGER']]) {
    if (!cols.includes(col)) db.exec(`ALTER TABLE devices ADD COLUMN ${col} ${type}`);
  }
  return db;
}
