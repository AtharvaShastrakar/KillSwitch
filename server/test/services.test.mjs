// Regression tests for the KillSwitch server workflow. Run: npm test  (node --test)
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from '../src/db.js';
import { loadSecrets, decrypt } from '../src/crypto.js';
import { createServices, S } from '../src/services.js';

const KEY_A = '111111-111111-111111-111111-111111-111111-111111-111111';
const KEY_B = '366586-075152-655435-422587-094974-614284-201135-301576';
const ID_A = '{29FFE490-5071-4C60-BE5A-99811F2C64D5}';
const ID_B = '{E7AB6754-E354-4B9D-952A-7DE9AD08C5DB}';

function setup(over = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ks-test-'));
  const config = { dayMs: 1000, graceDays: 10, wipeAfterLockDays: 20, leaseDays: 7, requiredWipeApprovals: 2,
    wipeMaxPerHour: 3, commandTtlMs: 3600_000, lockMessage: 'locked', tzOffset: '+05:30', ...over };
  const db = openDb(dir);
  const secrets = loadSecrets(dir);
  const svc = createServices({ db, secrets, config });
  db.prepare("INSERT INTO admins (id, username, pw_hash, created_at) VALUES (1,'admin1','x',0),(2,'admin2','x',0)").run();
  return { svc, db, secrets, config };
}
const enrollOne = (svc, serial = 'SER1') =>
  svc.enroll({ enrollmentToken: svc.createEnrollToken(1, 5, 24), serial, hostname: 'h', os: 'windows/amd64' });
const dev = (svc, id) => svc.getDevice(id);
const storedKey = (svc, secrets, id) => decrypt(secrets.masterKey, dev(svc, id).recovery_key_enc);
const cmdIdOf = (env) => JSON.parse(Buffer.from(env.payload, 'base64')).id;

test('escrow is confirmed only when the server holds the key that is on the laptop now', () => {
  const { svc, secrets } = setup();
  const { deviceId } = enrollOne(svc);
  assert.equal(svc.heartbeat(dev(svc, deviceId), { recoveryKeyId: ID_A, recoveryKey: KEY_A }).escrowConfirmed, true);
  assert.equal(svc.heartbeat(dev(svc, deviceId), { recoveryKeyId: ID_A }).escrowConfirmed, true);
  // Key rotated on the laptop (unlock / BitLocker re-enabled): server must say "not confirmed".
  assert.equal(svc.heartbeat(dev(svc, deviceId), { recoveryKeyId: ID_B }).escrowConfirmed, false);
  assert.equal(svc.heartbeat(dev(svc, deviceId), { recoveryKeyId: ID_B, recoveryKey: KEY_B }).escrowConfirmed, true);
  assert.equal(storedKey(svc, secrets, deviceId), KEY_B);
});

test('a dry-run fake key is replaced by the real key after switching to real mode (bug #1)', () => {
  const { svc, secrets } = setup();
  const { deviceId } = enrollOne(svc);
  svc.heartbeat(dev(svc, deviceId), { recoveryKeyId: 'dry-run-3fa2', recoveryKey: KEY_A, dryRun: true });
  const r = svc.heartbeat(dev(svc, deviceId), { recoveryKeyId: ID_B, dryRun: false });
  assert.equal(r.escrowConfirmed, false, 'real agent must be asked for its real key');
  svc.heartbeat(dev(svc, deviceId), { recoveryKeyId: ID_B, recoveryKey: KEY_B });
  assert.equal(storedKey(svc, secrets, deviceId), KEY_B);
});

test('a garbled key is rejected and never reported as escrowed (bug #2)', () => {
  const { svc, secrets } = setup();
  const { deviceId } = enrollOne(svc);
  svc.heartbeat(dev(svc, deviceId), { recoveryKeyId: ID_A, recoveryKey: KEY_A });
  const noisy = `WARNING: ACTIONS REQUIRED:\n 1. Save this numerical recovery password ...\n${KEY_B}\n`;
  const r = svc.heartbeat(dev(svc, deviceId), { recoveryKeyId: ID_B, recoveryKey: noisy });
  assert.equal(r.escrowConfirmed, false);
  assert.equal(storedKey(svc, secrets, deviceId), KEY_A, 'garbage must not overwrite the stored key');
});

test('a lock that fails on the laptop is not shown as confirmed (bug #4)', () => {
  const { svc } = setup();
  const { deviceId } = enrollOne(svc);
  svc.tx(() => svc.lockDevice(deviceId, 'admin:admin1', 'test'));
  const id = cmdIdOf(svc.heartbeat(dev(svc, deviceId), {}).commands[0]);
  svc.ack(dev(svc, deviceId), { commandId: id, ok: true, result: 'locked' });
  assert.ok(dev(svc, deviceId).lock_confirmed_at);
  svc.ack(dev(svc, deviceId), { commandId: id, ok: false, result: 'TPM protector is still present' });
  assert.equal(dev(svc, deviceId).lock_confirmed_at, null);
  const alerts = svc.q("SELECT COUNT(*) AS n FROM audit WHERE action = 'ALERT_LOCK_FAILED'").get().n;
  assert.equal(alerts, 1);
});

test('an existing laptop cannot be re-enrolled without admin approval (bug #3)', () => {
  const { svc, secrets } = setup();
  const real = enrollOne(svc, 'REAL');
  svc.heartbeat(dev(svc, real.deviceId), { recoveryKeyId: ID_A, recoveryKey: KEY_A });
  assert.throws(() => enrollOne(svc, 'REAL'), (e) => e.status === 409);
  assert.ok(svc.deviceFromToken(real.deviceToken), 'real laptop keeps working');
  assert.equal(storedKey(svc, secrets, real.deviceId), KEY_A);
  assert.equal(svc.q("SELECT COUNT(*) AS n FROM audit WHERE action = 'ALERT_REENROLL_BLOCKED'").get().n, 1);
  // After an admin allows it (e.g. Windows reinstalled), re-enrollment works once.
  svc.allowReenroll(real.deviceId, 'admin:admin1');
  const again = enrollOne(svc, 'REAL');
  assert.equal(again.deviceId, real.deviceId);
  assert.equal(dev(svc, real.deviceId).reenroll_until, null);
  assert.throws(() => enrollOne(svc, 'REAL'), (e) => e.status === 409);
});

test('cancelling an exit returns a locked laptop to normal and it is not re-locked (bug #5)', () => {
  const { svc, db } = setup();
  const { deviceId } = enrollOne(svc);
  const emp = svc.createEmployee({ empCode: 'E1', name: 'Asha' }, 'x');
  svc.assignDevice(deviceId, emp.id, 'x');
  svc.offboardEmployee(emp.id, Date.now() - 1, 'x');
  svc.tick();
  db.prepare('UPDATE devices SET grace_ends_at = 0 WHERE id = ?').run(deviceId);
  svc.tick();
  assert.equal(dev(svc, deviceId).state, S.LOCKED);
  const lockId = cmdIdOf(svc.heartbeat(dev(svc, deviceId), {}).commands[0]);
  svc.ack(dev(svc, deviceId), { commandId: lockId, ok: true, result: 'locked' });

  svc.cancelOffboarding(emp.id, 'admin:admin1');
  assert.equal(svc.getEmployee(emp.id).status, 'ACTIVE');
  assert.equal(dev(svc, deviceId).state, S.ACTIVE);
  const hb = svc.heartbeat(dev(svc, deviceId), {});
  assert.equal(JSON.parse(Buffer.from(hb.commands[0].payload, 'base64')).action, 'unlock');
  assert.ok(hb.lease, 'active laptop gets a lease again');
  svc.tick();
  assert.equal(dev(svc, deviceId).state, S.ACTIVE);
});

test('a wipe held by the mass-wipe limit is retried later (bug #6)', (t) => {
  const { svc } = setup({ wipeMaxPerHour: 1 });
  const a = enrollOne(svc, 'A').deviceId;
  const b = enrollOne(svc, 'B').deviceId;
  for (const id of [a, b]) { svc.tx(() => svc.lockDevice(id, 'x', 't')); svc.tx(() => svc.requestWipe(id, 'x')); }
  for (const id of [a, b]) { svc.approveWipe(id, { id: 1, username: 'admin1' }); svc.approveWipe(id, { id: 2, username: 'admin2' }); }
  assert.equal(dev(svc, a).state, S.WIPED);
  assert.equal(dev(svc, b).state, S.WIPE_PENDING, 'second wipe is held');
  svc.tick();
  assert.equal(dev(svc, b).state, S.WIPE_PENDING, 'still held within the hour');
  assert.equal(svc.q("SELECT COUNT(*) AS n FROM audit WHERE action = 'ALERT_WIPE_RATE_LIMIT'").get().n, 1, 'alert raised once, not every tick');
  const realNow = Date.now;
  t.after(() => { Date.now = realNow; });
  Date.now = () => realNow() + 61 * 60 * 1000; // an hour later
  svc.tick();
  assert.equal(dev(svc, b).state, S.WIPED);
});

test('last working day ends at 23:59:59 India time, not server time (bug #7)', () => {
  const { svc } = setup();
  assert.equal(new Date(svc.parseLastDay('2026-12-15')).toISOString(), '2026-12-15T18:29:59.000Z');
  assert.ok(Number.isNaN(svc.parseLastDay('15/12/2026')));
});
