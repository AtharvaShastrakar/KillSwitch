import { Router } from 'express';
import { verifyHmac } from '../crypto.js';
import { HttpError } from '../services.js';

// HR system webhook (Keka / Darwinbox / SAP ... via their webhook feature or a small connector).
// Header  X-Signature: hex(HMAC-SHA256(rawBody, HR_WEBHOOK_SECRET))
// Events:
//   { "event": "employee.created", "empCode": "E101", "name": "Asha", "email": "asha@co.com" }
//   { "event": "employee.exit", "empCode": "E101", "lastWorkingDay": "2026-12-15" }
//   { "event": "employee.exit_cancelled", "empCode": "E101" }
export function hrRouter(svc, secret, config) {
  const r = Router();
  r.post('/webhook', (req, res) => {
    const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.from('');
    if (!verifyHmac(secret, raw, req.get('x-signature'))) throw new HttpError(401, 'bad signature');
    let evt;
    try { evt = JSON.parse(raw.toString('utf8')); } catch { throw new HttpError(400, 'invalid JSON'); }

    if (evt.event === 'employee.created') {
      return res.json(svc.createEmployee(evt, 'hr-webhook'));
    }
    if (evt.event === 'employee.exit') {
      const emp = svc.q('SELECT * FROM employees WHERE emp_code = ?').get(String(evt.empCode || ''));
      if (!emp) throw new HttpError(404, 'unknown employee code');
      let lastDay;
      if (evt.lastWorkingDay) {
        // End of the last working day (23:59:59 in the company timezone, TZ_OFFSET).
        lastDay = svc.parseLastDay(String(evt.lastWorkingDay));
      } else if (evt.lastDayInDays != null) {
        lastDay = Date.now() + Number(evt.lastDayInDays) * config.dayMs;
      }
      return res.json(svc.offboardEmployee(emp.id, lastDay, 'hr-webhook'));
    }
    if (evt.event === 'employee.exit_cancelled') {
      const emp = svc.q('SELECT * FROM employees WHERE emp_code = ?').get(String(evt.empCode || ''));
      if (!emp) throw new HttpError(404, 'unknown employee code');
      return res.json(svc.cancelOffboarding(emp.id, 'hr-webhook'));
    }
    throw new HttpError(400, 'unsupported event');
  });
  return r;
}
