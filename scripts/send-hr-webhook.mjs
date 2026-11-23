// Simulates your HR system calling KillSwitch.
// Usage:
//   node scripts/send-hr-webhook.mjs <serverUrl> <secret> create E101 "Asha Rao" asha@company.com
//   node scripts/send-hr-webhook.mjs <serverUrl> <secret> exit E101 2026-12-15
//   node scripts/send-hr-webhook.mjs <serverUrl> <secret> exit E101 --in-days 1     (demo mode)
import crypto from 'node:crypto';

const [server, secret, kind, empCode, a, b] = process.argv.slice(2);
if (!server || !secret || !kind || !empCode) {
  console.error('usage: send-hr-webhook.mjs <serverUrl> <secret> create|exit <empCode> ...');
  process.exit(1);
}
const body = kind === 'create'
  ? { event: 'employee.created', empCode, name: a, email: b }
  : a === '--in-days'
    ? { event: 'employee.exit', empCode, lastDayInDays: Number(b) }
    : { event: 'employee.exit', empCode, lastWorkingDay: a };
const raw = JSON.stringify(body);
const sig = crypto.createHmac('sha256', secret).update(raw).digest('hex');
const res = await fetch(`${server.replace(/\/$/, '')}/api/hr/webhook`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Signature': sig }, body: raw,
});
console.log(res.status, await res.text());
