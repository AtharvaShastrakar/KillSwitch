const num = (name, def) => {
  const v = process.env[name];
  if (v === undefined || v === '') return def;
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`Invalid ${name}: ${v}`);
  return n;
};

export function loadConfig() {
  const dayMs = num('DAY_MS', 86_400_000);
  const port = num('PORT', 8080);
  // Timezone used to interpret "last working day" dates (end of day 23:59:59 in this offset).
  const tzOffset = process.env.TZ_OFFSET || '+05:30';
  if (!/^[+-]\d{2}:\d{2}$/.test(tzOffset)) throw new Error(`Invalid TZ_OFFSET: ${tzOffset} (use e.g. +05:30)`);
  return {
    port,
    dataDir: process.env.DATA_DIR || './data',
    publicUrl: process.env.PUBLIC_URL || `http://localhost:${port}`,
    dayMs,
    tzOffset,
    graceDays: num('GRACE_DAYS', 10),
    wipeAfterLockDays: num('WIPE_AFTER_LOCK_DAYS', 20),
    leaseDays: num('LEASE_DAYS', 7),
    requiredWipeApprovals: num('REQUIRED_WIPE_APPROVALS', 2),
    wipeMaxPerHour: num('WIPE_MAX_PER_HOUR', 3),
    commandTtlMs: num('COMMAND_TTL_MS', 60 * 60 * 1000),
    sessionTtlMs: num('SESSION_TTL_MS', 8 * 60 * 60 * 1000),
    // Workflow checks run 4x per "day", at least every second and at most every minute.
    tickMs: Math.min(60_000, Math.max(1_000, Math.floor(dayMs / 4))),
    lockMessage:
      process.env.LOCK_MESSAGE ||
      'This laptop is company property and has been locked. Please contact IT to return it.',
  };
}
