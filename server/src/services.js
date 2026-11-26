import crypto from 'node:crypto';
import { encrypt, decrypt, signEnvelope, sha256, randomToken } from './crypto.js';

// Device states
export const S = {
  ACTIVE: 'ACTIVE',               // in normal use
  OFFBOARDING: 'OFFBOARDING',     // employee has resigned, still working
  GRACE: 'GRACE',                 // last day passed, waiting for return (10 days)
  LOCKED: 'LOCKED',               // lock ordered (reversible)
  WIPE_PENDING: 'WIPE_PENDING',   // wipe deadline passed, waiting for approvals
  WIPED: 'WIPED',                 // keys destroyed + wipe ordered (irreversible)
  RETURNED: 'RETURNED',           // physically back with IT
};

// A BitLocker recovery password: 8 groups of 6 digits.
const RECOVERY_KEY_RE = /^\d{6}(-\d{6}){7}$/;
// A key protector ID as reported by the agent, e.g. {29FFE490-5071-4C60-BE5A-99811F2C64D5}.
const KEY_ID_RE = /^[A-Za-z0-9{}-]{1,80}$/;

// States in which a laptop keeps receiving a fresh offline lease.
const LEASE_STATES = new Set([S.ACTIVE, S.OFFBOARDING, S.GRACE, S.RETURNED]);

export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export function createServices({ db, secrets, config }) {
  const now = () => Date.now();
  const q = (sql) => db.prepare(sql);

  function tx(fn) {
    db.exec('BEGIN IMMEDIATE');
    try {
      const r = fn();
      db.exec('COMMIT');
      return r;
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
  }

  function audit(actor, action, { deviceId = null, employeeId = null, details = null } = {}) {
    q('INSERT INTO audit (ts, actor, action, device_id, employee_id, details) VALUES (?,?,?,?,?,?)').run(
      now(), actor, action, deviceId, employeeId,
      details == null ? null : typeof details === 'string' ? details : JSON.stringify(details),
    );
  }

  const getDevice = (id) => {
    const d = q('SELECT * FROM devices WHERE id = ?').get(id);
    if (!d) throw new HttpError(404, 'device not found');
    return d;
  };
  const getEmployee = (id) => {
    const e = q('SELECT * FROM employees WHERE id = ?').get(id);
    if (!e) throw new HttpError(404, 'employee not found');
    return e;
  };

  function setState(deviceId, state, extra = {}) {
    const cols = Object.keys(extra);
    const sets = ['state = ?', 'state_changed_at = ?', ...cols.map((c) => `${c} = ?`)].join(', ');
    q(`UPDATE devices SET ${sets} WHERE id = ?`).run(state, now(), ...cols.map((c) => extra[c]), deviceId);
  }

  function cancelPending(deviceId) {
    q("UPDATE commands SET status = 'cancelled' WHERE device_id = ? AND status IN ('queued','sent')").run(deviceId);
  }

  function queueCommand(deviceId, action) {
    cancelPending(deviceId); // newest instruction wins
    const id = crypto.randomUUID();
    q("INSERT INTO commands (id, device_id, action, status, created_at) VALUES (?,?,?,'queued',?)").run(
      id, deviceId, action, now(),
    );
    return id;
  }

  // ---------- Employees / HR ----------

  // "YYYY-MM-DD" -> end of that day (23:59:59) in the company's timezone (config.tzOffset).
  function parseLastDay(dateStr) {
    if (typeof dateStr !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return NaN;
    return new Date(`${dateStr}T23:59:59${config.tzOffset}`).getTime();
  }

  function createEmployee({ empCode, name, email }, actor) {
    if (!empCode || !name) throw new HttpError(400, 'empCode and name are required');
    try {
      const r = q('INSERT INTO employees (emp_code, name, email, created_at) VALUES (?,?,?,?)').run(
        String(empCode).trim(), String(name).trim(), email ? String(email).trim() : null, now(),
      );
      audit(actor, 'EMPLOYEE_CREATED', { employeeId: Number(r.lastInsertRowid), details: { empCode, name } });
      return getEmployee(Number(r.lastInsertRowid));
    } catch (e) {
      if (String(e.message).includes('UNIQUE')) throw new HttpError(409, 'employee code already exists');
      throw e;
    }
  }

  function offboardEmployee(employeeId, lastDay, actor) {
    return tx(() => {
      const emp = getEmployee(employeeId);
      if (emp.status === 'LEFT') throw new HttpError(409, 'employee has already left');
      if (!Number.isFinite(lastDay)) throw new HttpError(400, 'invalid last working day');
      q("UPDATE employees SET status = 'OFFBOARDING', last_day = ? WHERE id = ?").run(lastDay, employeeId);
      const devices = q('SELECT * FROM devices WHERE employee_id = ? AND state = ?').all(employeeId, S.ACTIVE);
      for (const d of devices) setState(d.id, S.OFFBOARDING);
      audit(actor, 'OFFBOARDING_STARTED', {
        employeeId,
        details: { lastDay: new Date(lastDay).toISOString(), devices: devices.map((d) => d.serial) },
      });
      return getEmployee(employeeId);
    });
  }

  // Exit cancelled (employee is staying): employee back to ACTIVE, laptops back to normal.
  function cancelOffboarding(employeeId, actor) {
    return tx(() => {
      const emp = getEmployee(employeeId);
      if (!['OFFBOARDING', 'LEFT'].includes(emp.status)) throw new HttpError(409, 'employee is not being offboarded');
      q("UPDATE employees SET status = 'ACTIVE', last_day = NULL WHERE id = ?").run(employeeId);
      const changed = [];
      for (const d of q('SELECT * FROM devices WHERE employee_id = ?').all(employeeId)) {
        if (d.state === S.WIPED || d.state === S.ACTIVE) continue;
        q('DELETE FROM wipe_approvals WHERE device_id = ?').run(d.id);
        // If a lock already ran on the laptop, the agent must restore its TPM protector.
        if (d.lock_confirmed_at) queueCommand(d.id, 'unlock');
        else cancelPending(d.id);
        setState(d.id, S.ACTIVE, { grace_ends_at: null, wipe_due_at: null, lock_confirmed_at: null });
        changed.push({ serial: d.serial, from: d.state, unlockQueued: !!d.lock_confirmed_at });
      }
      audit(actor, 'OFFBOARDING_CANCELLED', { employeeId, details: { previousStatus: emp.status, devices: changed } });
      return getEmployee(employeeId);
    });
  }

  // ---------- Device actions ----------

  // A laptop that is already enrolled can only be enrolled again after an admin allows it
  // (e.g. Windows was reinstalled). This stops anyone with an enrollment token from taking over
  // another laptop's record or overwriting its escrowed recovery key.
  function allowReenroll(deviceId, actor) {
    const d = getDevice(deviceId);
    q('UPDATE devices SET reenroll_until = ? WHERE id = ?').run(now() + 24 * 3600_000, deviceId);
    audit(actor, 'REENROLL_ALLOWED', { deviceId, employeeId: d.employee_id, details: { serial: d.serial, validHours: 24 } });
    return getDevice(deviceId);
  }

  function assignDevice(deviceId, employeeId, actor) {
    return tx(() => {
      const d = getDevice(deviceId);
      if (![S.ACTIVE, S.RETURNED].includes(d.state)) {
        throw new HttpError(409, `cannot assign a device in state ${d.state}`);
      }
      let emp = null;
      if (employeeId != null) {
        emp = getEmployee(employeeId);
        if (emp.status !== 'ACTIVE') throw new HttpError(409, 'can only assign to an active employee');
      }
      setState(deviceId, S.ACTIVE, {
        employee_id: emp ? emp.id : null, grace_ends_at: null, wipe_due_at: null, lock_confirmed_at: null,
      });
      audit(actor, 'DEVICE_ASSIGNED', { deviceId, employeeId: emp?.id, details: { serial: d.serial } });
      return getDevice(deviceId);
    });
  }

  function lockDevice(deviceId, actor, reason) {
    const d = getDevice(deviceId);
    if ([S.WIPED, S.LOCKED, S.WIPE_PENDING].includes(d.state)) return d;
    setState(deviceId, S.LOCKED, { wipe_due_at: now() + config.wipeAfterLockDays * config.dayMs });
    const cmd = queueCommand(deviceId, 'lock');
    audit(actor, 'LOCK_ORDERED', { deviceId, employeeId: d.employee_id, details: { reason, commandId: cmd } });
    return getDevice(deviceId);
  }

  function cancelLock(deviceId, actor) {
    return tx(() => {
      const d = getDevice(deviceId);
      if (![S.LOCKED, S.WIPE_PENDING].includes(d.state)) throw new HttpError(409, 'device is not locked');
      const emp = d.employee_id ? getEmployee(d.employee_id) : null;
      const back = emp && emp.status === 'LEFT' ? S.GRACE : emp && emp.status === 'OFFBOARDING' ? S.OFFBOARDING : S.ACTIVE;
      q('DELETE FROM wipe_approvals WHERE device_id = ?').run(deviceId);
      // If the lock already ran on the laptop, tell the agent to restore its TPM protector.
      if (d.lock_confirmed_at) queueCommand(deviceId, 'unlock');
      else cancelPending(deviceId);
      setState(deviceId, back, {
        wipe_due_at: null, lock_confirmed_at: null,
        // Restarting grace after a manual cancel gives a fresh 10 days.
        grace_ends_at: back === S.GRACE ? now() + config.graceDays * config.dayMs : d.grace_ends_at,
      });
      audit(actor, 'LOCK_CANCELLED', { deviceId, employeeId: d.employee_id, details: { newState: back } });
      return getDevice(deviceId);
    });
  }

  function requestWipe(deviceId, actor) {
    const d = getDevice(deviceId);
    if (d.state !== S.LOCKED) throw new HttpError(409, 'only a locked device can be sent for wipe approval');
    setState(deviceId, S.WIPE_PENDING);
    audit(actor, 'WIPE_REQUESTED', { deviceId, employeeId: d.employee_id });
    return getDevice(deviceId);
  }

  function approveWipe(deviceId, admin) {
    return tx(() => {
      const d = getDevice(deviceId);
      if (d.state !== S.WIPE_PENDING) throw new HttpError(409, 'device is not waiting for wipe approval');
      try {
        q('INSERT INTO wipe_approvals (device_id, admin_id, created_at) VALUES (?,?,?)').run(deviceId, admin.id, now());
      } catch (e) {
        if (String(e.message).includes('UNIQUE') || String(e.message).includes('PRIMARY')) {
          throw new HttpError(409, 'you have already approved this wipe; a different admin must approve');
        }
        throw e;
      }
      const count = q('SELECT COUNT(*) AS n FROM wipe_approvals WHERE device_id = ?').get(deviceId).n;
      audit(`admin:${admin.username}`, 'WIPE_APPROVED', {
        deviceId, employeeId: d.employee_id, details: { approvals: count, required: config.requiredWipeApprovals },
      });
      if (count >= config.requiredWipeApprovals) executeWipe(deviceId);
      return getDevice(deviceId);
    });
  }

  function executeWipe(deviceId) {
    const d = getDevice(deviceId);
    const hourAgo = now() - 60 * 60 * 1000;
    const recent = q("SELECT COUNT(*) AS n FROM audit WHERE action = 'WIPE_EXECUTED' AND ts > ?").get(hourAgo).n;
    if (recent >= config.wipeMaxPerHour) {
      // Mass-wipe protection: leave it pending (tick() retries it later) and raise an alert once.
      const alerted = q("SELECT 1 FROM audit WHERE action = 'ALERT_WIPE_RATE_LIMIT' AND device_id = ? AND ts > ?").get(deviceId, hourAgo);
      if (!alerted) {
        audit('system', 'ALERT_WIPE_RATE_LIMIT', {
          deviceId, details: `More than ${config.wipeMaxPerHour} wipes in one hour; wipe held and retried automatically`,
        });
      }
      return;
    }
    // Crypto-shred: destroying the escrowed recovery key makes a TPM-less (locked) disk unrecoverable,
    // even if the laptop never comes online again. The agent also runs a factory reset if it can.
    setState(deviceId, S.WIPED, { recovery_key_enc: null });
    queueCommand(deviceId, 'wipe');
    audit('system', 'WIPE_EXECUTED', {
      deviceId, employeeId: d.employee_id, details: 'escrowed recovery key destroyed; wipe command queued',
    });
  }

  function markReturned(deviceId, actor) {
    return tx(() => {
      const d = getDevice(deviceId);
      if (d.state === S.WIPED) {
        // Wiped laptops can come back too; they just need re-imaging.
        cancelPending(deviceId);
      } else if (d.lock_confirmed_at) {
        // IT enters the recovery key at boot; then the agent restores the TPM protector.
        queueCommand(deviceId, 'unlock');
      } else {
        cancelPending(deviceId);
      }
      q('DELETE FROM wipe_approvals WHERE device_id = ?').run(deviceId);
      setState(deviceId, S.RETURNED, { employee_id: null, grace_ends_at: null, wipe_due_at: null });
      audit(actor, 'DEVICE_RETURNED', { deviceId, employeeId: d.employee_id, details: { previousState: d.state } });
      return getDevice(deviceId);
    });
  }

  function revealRecoveryKey(deviceId, actor) {
    const d = getDevice(deviceId);
    if (!d.recovery_key_enc) throw new HttpError(404, 'no recovery key escrowed for this device');
    audit(actor, 'RECOVERY_KEY_REVEALED', { deviceId, employeeId: d.employee_id });
    return decrypt(secrets.masterKey, d.recovery_key_enc);
  }

  // ---------- Agent protocol ----------

  function createEnrollToken(adminId, uses = 10, hours = 24) {
    const token = randomToken(24);
    q('INSERT INTO enroll_tokens (token_hash, created_by, expires_at, uses_left) VALUES (?,?,?,?)').run(
      sha256(token), adminId, now() + hours * 3600_000, uses,
    );
    return token;
  }

  function enroll({ enrollmentToken, serial, hostname, os, agentVersion }) {
    if (!enrollmentToken || !serial) throw new HttpError(400, 'enrollmentToken and serial are required');
    const result = tx(() => {
      const t = q('SELECT * FROM enroll_tokens WHERE token_hash = ?').get(sha256(String(enrollmentToken)));
      if (!t || t.expires_at < now() || t.uses_left <= 0) throw new HttpError(401, 'invalid or expired enrollment token');

      const existing = q('SELECT * FROM devices WHERE serial = ?').get(String(serial));
      if (existing && existing.token_hash && !(existing.reenroll_until > now())) {
        return { blocked: existing };
      }
      q('UPDATE enroll_tokens SET uses_left = uses_left - 1 WHERE token_hash = ?').run(t.token_hash);

      const deviceToken = randomToken(32);
      let deviceId;
      if (existing) {
        // Re-enrollment (e.g. OS reinstalled). The device KEEPS its state, so a missing laptop
        // that gets reinstalled is locked again as soon as the agent comes back.
        deviceId = existing.id;
        q('UPDATE devices SET token_hash = ?, hostname = ?, os = ?, agent_version = ?, last_seen = ?, reenroll_until = NULL WHERE id = ?').run(
          sha256(deviceToken), hostname || null, os || null, agentVersion || null, now(), deviceId,
        );
        if ([S.LOCKED, S.WIPE_PENDING, S.WIPED].includes(existing.state)) {
          q('UPDATE devices SET lock_confirmed_at = NULL WHERE id = ?').run(deviceId);
          queueCommand(deviceId, 'lock');
        }
        audit('agent', 'DEVICE_REENROLLED', { deviceId, details: { serial, hostname, state: existing.state } });
      } else {
        const r = q(
          'INSERT INTO devices (serial, hostname, os, state, token_hash, enrolled_at, last_seen, state_changed_at, agent_version) VALUES (?,?,?,?,?,?,?,?,?)',
        ).run(String(serial), hostname || null, os || null, S.ACTIVE, sha256(deviceToken), now(), now(), now(), agentVersion || null);
        deviceId = Number(r.lastInsertRowid);
        audit('agent', 'DEVICE_ENROLLED', { deviceId, details: { serial, hostname, os } });
      }
      return { deviceId, deviceToken, serverTime: now() };
    });
    if (result.blocked) {
      audit('agent', 'ALERT_REENROLL_BLOCKED', {
        deviceId: result.blocked.id, employeeId: result.blocked.employee_id,
        details: { serial: String(serial), hostname: hostname || null, note: 'laptop already enrolled; an admin must click "Allow re-enroll" first' },
      });
      throw new HttpError(409, 'this laptop is already enrolled; an admin must allow re-enrollment on the dashboard first');
    }
    return result;
  }

  function deviceFromToken(token) {
    if (!token) return null;
    return q('SELECT * FROM devices WHERE token_hash = ?').get(sha256(token)) || null;
  }

  function heartbeat(device, body = {}) {
    return tx(() => {
      const t = now();
      // ID of the recovery password currently on the laptop (agents >= 0.2.0 send it every time).
      const reportedId = typeof body.recoveryKeyId === 'string' && KEY_ID_RE.test(body.recoveryKeyId) ? body.recoveryKeyId : null;
      q('UPDATE devices SET last_seen = ?, hostname = COALESCE(?, hostname), agent_version = COALESCE(?, agent_version), last_report = ?, reported_key_id = ? WHERE id = ?').run(
        t, body.hostname || null, body.agentVersion || null,
        JSON.stringify({ lockState: body.lockState, encryption: body.encryption, dryRun: body.dryRun }), reportedId, device.id,
      );
      let keyRejected = false;
      if (body.recoveryKey !== undefined && body.recoveryKey !== null) {
        const fresh = getDevice(device.id);
        const key = typeof body.recoveryKey === 'string' ? body.recoveryKey.trim() : '';
        if (fresh.state === S.WIPED) {
          // keys of wiped laptops stay destroyed
        } else if (!RECOVERY_KEY_RE.test(key)) {
          // Never store garbage, and never tell the agent it was stored (see escrowConfirmed below).
          keyRejected = true;
          audit('agent', 'ALERT_RECOVERY_KEY_REJECTED', { deviceId: device.id, details: { reason: 'not a 48-digit recovery password', length: key.length } });
        } else {
          q('UPDATE devices SET recovery_key_enc = ?, recovery_key_id = ? WHERE id = ?').run(encrypt(secrets.masterKey, key), reportedId, device.id);
          audit('agent', 'RECOVERY_KEY_ESCROWED', { deviceId: device.id, details: { keyId: reportedId, dryRun: !!body.dryRun } });
        }
      }
      const d = getDevice(device.id);
      // Confirmed only if the server holds the key that is CURRENTLY on the laptop. If the IDs differ
      // (dry-run fake key, key rotated, BitLocker re-enabled...) the agent re-sends the real key.
      const escrowConfirmed = !keyRejected && !!d.recovery_key_enc && (reportedId === null || d.recovery_key_id === reportedId);
      const res = {
        serverTime: t,
        state: d.state,
        escrowConfirmed,
        lockMessage: config.lockMessage,
        lease: null,
        commands: [],
      };
      if (LEASE_STATES.has(d.state)) {
        const expiresAt = t + config.leaseDays * config.dayMs;
        res.lease = signEnvelope(secrets.privateKey, {
          kind: 'lease', deviceId: d.id, serial: d.serial, issuedAt: t, expiresAt,
        });
        q('UPDATE devices SET lease_expires = ? WHERE id = ?').run(expiresAt, d.id);
      }
      const cmds = q("SELECT * FROM commands WHERE device_id = ? AND status IN ('queued','sent') ORDER BY created_at").all(d.id);
      for (const c of cmds) {
        res.commands.push(
          signEnvelope(secrets.privateKey, {
            kind: 'command', id: c.id, action: c.action, deviceId: d.id, serial: d.serial,
            issuedAt: t, expiresAt: t + config.commandTtlMs,
          }),
        );
        if (c.status === 'queued') q("UPDATE commands SET status = 'sent', sent_at = ? WHERE id = ?").run(t, c.id);
      }
      return res;
    });
  }

  function ack(device, { commandId, ok, result }) {
    return tx(() => {
      const c = q('SELECT * FROM commands WHERE id = ? AND device_id = ?').get(String(commandId), device.id);
      if (!c) throw new HttpError(404, 'command not found');
      if (c.status === 'cancelled') return { ignored: true };
      q('UPDATE commands SET status = ?, acked_at = ?, result = ? WHERE id = ?').run(
        ok ? 'done' : 'failed', now(), String(result ?? '').slice(0, 2000), c.id,
      );
      if (ok && c.action === 'lock') q('UPDATE devices SET lock_confirmed_at = ? WHERE id = ?').run(now(), device.id);
      if (!ok && c.action === 'lock') {
        // The laptop is NOT locked: never leave "Lock confirmed" on the dashboard.
        q('UPDATE devices SET lock_confirmed_at = NULL WHERE id = ?').run(device.id);
        audit('system', 'ALERT_LOCK_FAILED', { deviceId: device.id, details: { commandId: c.id, result: String(result ?? '').slice(0, 500) } });
      }
      if (ok && c.action === 'unlock') q('UPDATE devices SET lock_confirmed_at = NULL WHERE id = ?').run(device.id);
      audit('agent', ok ? `COMMAND_${c.action.toUpperCase()}_DONE` : `COMMAND_${c.action.toUpperCase()}_FAILED`, {
        deviceId: device.id, details: { commandId: c.id, result: String(result ?? '').slice(0, 500) },
      });
      return { ok: true };
    });
  }

  // ---------- Scheduled workflow ----------

  function tick() {
    const t = now();
    // 1) Last working day reached → employee LEFT, account disabled, devices enter the grace period.
    for (const emp of q("SELECT * FROM employees WHERE status = 'OFFBOARDING' AND last_day <= ?").all(t)) {
      tx(() => {
        q("UPDATE employees SET status = 'LEFT' WHERE id = ?").run(emp.id);
        // PROTOTYPE: here you would call Entra ID / Okta / Google Workspace to disable the account.
        audit('system', 'IDP_ACCOUNT_DISABLED', { employeeId: emp.id, details: `${emp.emp_code} (stub - connect your identity provider)` });
        const graceEnds = emp.last_day + config.graceDays * config.dayMs;
        for (const d of q('SELECT * FROM devices WHERE employee_id = ? AND state IN (?, ?)').all(emp.id, S.ACTIVE, S.OFFBOARDING)) {
          setState(d.id, S.GRACE, { grace_ends_at: graceEnds });
          audit('system', 'GRACE_PERIOD_STARTED', {
            deviceId: d.id, employeeId: emp.id, details: { graceDays: config.graceDays, endsAt: new Date(graceEnds).toISOString() },
          });
        }
      });
    }
    // 2) Grace period over and laptop not returned → lock.
    for (const d of q('SELECT * FROM devices WHERE state = ? AND grace_ends_at <= ?').all(S.GRACE, t)) {
      tx(() => lockDevice(d.id, 'system', `not returned within ${config.graceDays}-day grace period`));
    }
    // 3) Still missing after the wipe deadline → needs approval from admins.
    for (const d of q('SELECT * FROM devices WHERE state = ? AND wipe_due_at <= ?').all(S.LOCKED, t)) {
      tx(() => {
        setState(d.id, S.WIPE_PENDING);
        audit('system', 'WIPE_APPROVAL_REQUIRED', {
          deviceId: d.id, employeeId: d.employee_id,
          details: `still missing ${config.wipeAfterLockDays} days after lock; ${config.requiredWipeApprovals} admin approvals required`,
        });
      });
    }
    // 4) Wipes that are fully approved but were held by the mass-wipe limit: retry them.
    for (const d of q(`SELECT d.id FROM devices d WHERE d.state = ?
                       AND (SELECT COUNT(*) FROM wipe_approvals w WHERE w.device_id = d.id) >= ?`).all(S.WIPE_PENDING, config.requiredWipeApprovals)) {
      tx(() => executeWipe(d.id));
    }
  }

  return {
    S, audit, tick, parseLastDay, cancelOffboarding, allowReenroll, getDevice, getEmployee,
    createEmployee, offboardEmployee, assignDevice, lockDevice, cancelLock,
    requestWipe, approveWipe, markReturned, revealRecoveryKey,
    createEnrollToken, enroll, deviceFromToken, heartbeat, ack, tx, q,
  };
}
