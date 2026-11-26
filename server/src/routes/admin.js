import { Router } from 'express';
import { hashPassword, verifyPassword, randomToken, sha256 } from '../crypto.js';
import { HttpError } from '../services.js';

const COOKIE = 'ks_session';

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

// Never send token hashes or encrypted keys to the browser.
const clean = (d) => {
  if (!d || typeof d !== 'object') return d;
  const { token_hash, recovery_key_enc, ...rest } = d;
  return { ...rest, key_escrowed: !!recovery_key_enc };
};

export function adminRouter(svc, { config, secrets }) {
  const r = Router();
  const q = svc.q;

  // Simple per-IP login throttle.
  const attempts = new Map();
  r.post('/login', (req, res) => {
    const ip = req.ip;
    const a = attempts.get(ip) || { n: 0, until: 0 };
    if (a.until > Date.now()) throw new HttpError(429, 'too many attempts, try again in a minute');
    const { username, password } = req.body || {};
    const admin = q('SELECT * FROM admins WHERE username = ?').get(String(username || ''));
    if (!admin || !verifyPassword(String(password || ''), admin.pw_hash)) {
      a.n += 1;
      if (a.n >= 5) { a.until = Date.now() + 60_000; a.n = 0; }
      attempts.set(ip, a);
      svc.audit(`ip:${ip}`, 'ADMIN_LOGIN_FAILED', { details: { username } });
      throw new HttpError(401, 'invalid username or password');
    }
    attempts.delete(ip);
    const token = randomToken(32);
    q('INSERT INTO sessions (token_hash, admin_id, expires_at) VALUES (?,?,?)').run(sha256(token), admin.id, Date.now() + config.sessionTtlMs);
    svc.audit(`admin:${admin.username}`, 'ADMIN_LOGIN');
    const secure = config.publicUrl.startsWith('https') ? '; Secure' : '';
    res.setHeader('Set-Cookie', `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/${secure}; Max-Age=${Math.floor(config.sessionTtlMs / 1000)}`);
    res.json({ username: admin.username });
  });

  r.use((req, _res, next) => {
    const token = parseCookies(req.get('cookie'))[COOKIE];
    const s = token && q('SELECT * FROM sessions WHERE token_hash = ? AND expires_at > ?').get(sha256(token), Date.now());
    if (!s) return next(new HttpError(401, 'not logged in'));
    req.admin = q('SELECT id, username FROM admins WHERE id = ?').get(s.admin_id);
    req.actor = `admin:${req.admin.username}`;
    req.sessionHash = s.token_hash;
    next();
  });

  r.post('/logout', (req, res) => {
    q('DELETE FROM sessions WHERE token_hash = ?').run(req.sessionHash);
    res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
    res.json({ ok: true });
  });

  r.get('/me', (req, res) => res.json({
    username: req.admin.username,
    settings: {
      dayMs: config.dayMs, graceDays: config.graceDays, wipeAfterLockDays: config.wipeAfterLockDays,
      leaseDays: config.leaseDays, requiredWipeApprovals: config.requiredWipeApprovals,
    },
  }));

  r.post('/change-password', (req, res) => {
    const { newPassword } = req.body || {};
    if (!newPassword || String(newPassword).length < 12) throw new HttpError(400, 'password must be at least 12 characters');
    q('UPDATE admins SET pw_hash = ? WHERE id = ?').run(hashPassword(String(newPassword)), req.admin.id);
    svc.audit(req.actor, 'ADMIN_PASSWORD_CHANGED');
    res.json({ ok: true });
  });

  r.get('/devices', (req, res) => {
    res.json(q(`
      SELECT d.id, d.serial, d.hostname, d.os, d.state, d.employee_id, e.name AS employee_name, e.emp_code,
             d.last_seen, d.lease_expires, d.grace_ends_at, d.wipe_due_at, d.lock_confirmed_at, d.state_changed_at,
             d.agent_version, d.last_report, (d.recovery_key_enc IS NOT NULL) AS key_escrowed,
             (d.recovery_key_enc IS NOT NULL AND (d.reported_key_id IS NULL OR d.reported_key_id = d.recovery_key_id)) AS key_in_sync,
             d.reenroll_until,
             (SELECT COUNT(*) FROM wipe_approvals w WHERE w.device_id = d.id) AS wipe_approvals,
             (SELECT GROUP_CONCAT(a.username) FROM wipe_approvals w JOIN admins a ON a.id = w.admin_id WHERE w.device_id = d.id) AS approved_by,
             (SELECT c.action || ':' || c.status FROM commands c WHERE c.device_id = d.id ORDER BY c.created_at DESC LIMIT 1) AS last_command
      FROM devices d LEFT JOIN employees e ON e.id = d.employee_id
      ORDER BY d.id`).all());
  });

  r.get('/employees', (req, res) => {
    res.json(q(`SELECT e.*, (SELECT COUNT(*) FROM devices d WHERE d.employee_id = e.id) AS device_count
                FROM employees e ORDER BY e.id`).all());
  });

  r.post('/employees', (req, res) => res.json(svc.createEmployee(req.body || {}, req.actor)));

  r.post('/employees/:id/offboard', (req, res) => {
    const { lastWorkingDay, lastDayInDays } = req.body || {};
    let lastDay;
    if (lastDayInDays != null && lastDayInDays !== '') lastDay = Date.now() + Number(lastDayInDays) * config.dayMs;
    else if (lastWorkingDay) lastDay = svc.parseLastDay(String(lastWorkingDay));
    res.json(svc.offboardEmployee(Number(req.params.id), lastDay, req.actor));
  });
  r.post('/employees/:id/cancel-offboarding', (req, res) => res.json(svc.cancelOffboarding(Number(req.params.id), req.actor)));

  const id = (req) => Number(req.params.id);
  r.post('/devices/:id/assign', (req, res) => {
    const e = req.body?.employeeId;
    res.json(clean(svc.assignDevice(id(req), e === '' || e == null ? null : Number(e), req.actor)));
  });
  r.post('/devices/:id/lock', (req, res) => res.json(clean(svc.tx(() => svc.lockDevice(id(req), req.actor, req.body?.reason || 'manual lock')))));
  r.post('/devices/:id/cancel-lock', (req, res) => res.json(clean(svc.cancelLock(id(req), req.actor))));
  r.post('/devices/:id/request-wipe', (req, res) => res.json(clean(svc.tx(() => svc.requestWipe(id(req), req.actor)))));
  r.post('/devices/:id/approve-wipe', (req, res) => res.json(clean(svc.approveWipe(id(req), req.admin))));
  r.post('/devices/:id/returned', (req, res) => res.json(clean(svc.markReturned(id(req), req.actor))));
  r.post('/devices/:id/allow-reenroll', (req, res) => res.json(clean(svc.allowReenroll(id(req), req.actor))));
  r.post('/devices/:id/recovery-key', (req, res) => res.json({ recoveryKey: svc.revealRecoveryKey(id(req), req.actor) }));

  r.get('/audit', (req, res) => {
    const limit = Math.min(500, Number(req.query.limit) || 200);
    res.json(q(`SELECT a.*, d.serial, e.name AS employee_name FROM audit a
                LEFT JOIN devices d ON d.id = a.device_id LEFT JOIN employees e ON e.id = a.employee_id
                ORDER BY a.id DESC LIMIT ?`).all(limit));
  });

  r.post('/enroll-token', (req, res) => {
    const uses = Math.min(500, Math.max(1, Number(req.body?.uses) || 10));
    const hours = Math.min(24 * 30, Math.max(1, Number(req.body?.hours) || 24));
    const token = svc.createEnrollToken(req.admin.id, uses, hours);
    svc.audit(req.actor, 'ENROLL_TOKEN_CREATED', { details: { uses, hours } });
    res.json({
      token, uses, hours,
      agentConfig: {
        serverUrl: config.publicUrl,
        serverPublicKey: secrets.publicKeyB64,
        enrollmentToken: token,
        heartbeatSeconds: config.dayMs < 86_400_000 ? 3 : 900,
        dryRun: true,
      },
    });
  });

  r.get('/hr-webhook-info', (req, res) => {
    svc.audit(req.actor, 'HR_WEBHOOK_SECRET_VIEWED');
    res.json({ url: `${config.publicUrl}/api/hr/webhook`, secret: secrets.hrWebhookSecret });
  });

  return r;
}
