import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './config.js';
import { openDb } from './db.js';
import { loadSecrets, hashPassword, randomToken } from './crypto.js';
import { createServices, HttpError } from './services.js';
import { agentRouter } from './routes/agent.js';
import { adminRouter } from './routes/admin.js';
import { hrRouter } from './routes/hr.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const config = loadConfig();
const db = openDb(config.dataDir);
const secrets = loadSecrets(config.dataDir);
const svc = createServices({ db, secrets, config });

// First run: create two admins (two-person rule for wipes) with random passwords.
if (db.prepare('SELECT COUNT(*) AS n FROM admins').get().n === 0) {
  const lines = ['KillSwitch initial admin accounts (change these passwords after first login):'];
  for (const username of ['admin1', 'admin2']) {
    const pw = randomToken(12);
    db.prepare('INSERT INTO admins (username, pw_hash, created_at) VALUES (?,?,?)').run(username, hashPassword(pw), Date.now());
    lines.push(`  ${username} / ${pw}`);
  }
  const file = path.join(config.dataDir, 'initial-admins.txt');
  fs.writeFileSync(file, lines.join('\n') + '\n', { mode: 0o600 });
  console.log(`\n${lines.join('\n')}\n(also saved to ${file})\n`);
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 'loopback');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:");
  next();
});

app.use('/api/hr', express.raw({ type: () => true, limit: '64kb' }), hrRouter(svc, secrets.hrWebhookSecret, config));
app.use(express.json({ limit: '64kb' }));
app.use('/api/agent', agentRouter(svc));
app.use('/api/admin', adminRouter(svc, { config, secrets }));
app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.use(express.static(path.join(here, '..', 'public')));

app.use((err, _req, res, _next) => {
  const status = err instanceof HttpError ? err.status : err.type === 'entity.parse.failed' ? 400 : 500;
  if (status === 500) console.error(err);
  res.status(status).json({ error: status === 500 ? 'internal error' : err.message });
});

setInterval(() => {
  try { svc.tick(); } catch (e) { console.error('workflow tick failed:', e); }
}, config.tickMs);

app.listen(config.port, () => {
  const day = config.dayMs === 86_400_000 ? '1 day' : `${config.dayMs / 1000}s (DEMO MODE)`;
  console.log(`KillSwitch server on ${config.publicUrl}`);
  console.log(`Workflow: grace ${config.graceDays} days -> lock -> wipe approval after ${config.wipeAfterLockDays} more days. 1 "day" = ${day}`);
});
