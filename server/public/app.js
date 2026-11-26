'use strict';
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  let me = null;
  let employees = [];
  let lastDevices = [];
  let lastAudit = [];
  let currentTab = 'overview';
  let devFilter = 'ALL';

  const STATES = ['ACTIVE', 'OFFBOARDING', 'GRACE', 'LOCKED', 'WIPE_PENDING', 'WIPED', 'RETURNED'];
  const STATE_LABEL = {
    ACTIVE: 'Active', OFFBOARDING: 'Offboarding', GRACE: 'Grace period', LOCKED: 'Locked',
    WIPE_PENDING: 'Wipe pending', WIPED: 'Wiped', RETURNED: 'Returned',
  };
  const TITLES = { overview: 'Overview', devices: 'Laptops', employees: 'Employees', audit: 'Audit log', enroll: 'Enroll laptops' };
  const ACTION_LABEL = {
    ADMIN_LOGIN: 'Admin signed in', ADMIN_LOGIN_FAILED: 'Failed sign-in', ADMIN_PASSWORD_CHANGED: 'Password changed',
    EMPLOYEE_CREATED: 'Employee added', OFFBOARDING_STARTED: 'Offboarding started', OFFBOARDING_CANCELLED: 'Exit cancelled',
    IDP_ACCOUNT_DISABLED: 'Employee left', GRACE_PERIOD_STARTED: 'Grace period started',
    DEVICE_ENROLLED: 'Laptop enrolled', DEVICE_REENROLLED: 'Laptop re-enrolled', DEVICE_ASSIGNED: 'Laptop assigned',
    DEVICE_RETURNED: 'Laptop returned', LOCK_ORDERED: 'Lock ordered', LOCK_CANCELLED: 'Lock cancelled',
    COMMAND_LOCK_DONE: 'Laptop locked', COMMAND_LOCK_FAILED: 'Lock failed', COMMAND_UNLOCK_DONE: 'Laptop restored',
    COMMAND_UNLOCK_FAILED: 'Restore failed', COMMAND_WIPE_DONE: 'Wipe started on laptop',
    WIPE_REQUESTED: 'Wipe requested', WIPE_APPROVAL_REQUIRED: 'Wipe approval needed', WIPE_APPROVED: 'Wipe approved',
    WIPE_EXECUTED: 'Wipe executed', RECOVERY_KEY_ESCROWED: 'Recovery key saved', RECOVERY_KEY_REVEALED: 'Recovery key viewed',
    REENROLL_ALLOWED: 'Re-enroll allowed', ENROLL_TOKEN_CREATED: 'Enrollment token created',
    HR_WEBHOOK_SECRET_VIEWED: 'HR webhook secret viewed',
    ALERT_LOCK_FAILED: '⚠ Lock failed', ALERT_REENROLL_BLOCKED: '⚠ Re-enroll blocked',
    ALERT_RECOVERY_KEY_REJECTED: '⚠ Invalid recovery key rejected', ALERT_WIPE_RATE_LIMIT: '⚠ Wipe held (rate limit)',
  };
  const actionLabel = (a) => ACTION_LABEL[a] || a.replace(/_/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase());

  async function api(path, opts = {}) {
    const res = await fetch(`/api/admin${path}`, {
      method: opts.method || (opts.body ? 'POST' : 'GET'),
      headers: opts.body ? { 'Content-Type': 'application/json' } : {},
      body: opts.body ? JSON.stringify(opts.body) : undefined,
      credentials: 'same-origin',
    });
    const data = await res.json().catch(() => ({}));
    if (res.status === 401 && path !== '/login') { showLogin(); throw new Error('Session expired'); }
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  function flash(msg, ok = true) {
    const f = $('#flash');
    f.textContent = msg;
    f.className = `flash ${ok ? 'ok' : 'err'}`;
    clearTimeout(flash.t);
    flash.t = setTimeout(() => f.classList.add('hidden'), 5000);
  }

  function dialog(title, html, okLabel = 'OK', danger = false) {
    return new Promise((resolve) => {
      const d = $('#dialog');
      $('#dialog-title').textContent = title;
      $('#dialog-content').innerHTML = html;
      const ok = $('#dialog-ok');
      ok.textContent = okLabel;
      ok.className = `btn ${danger ? 'danger-solid' : 'primary'}`;
      d.onclose = () => resolve(d.returnValue === 'ok' ? new FormData($('.dialog-body')) : null);
      d.returnValue = '';
      d.showModal();
    });
  }

  // ----- time helpers -----
  const fmtTime = (ms) => (ms ? new Date(ms).toLocaleString() : '—');
  const fmtDate = (ms) => (ms ? new Date(ms).toLocaleDateString() : '—');
  function fmtLeft(ms) {
    const left = ms - Date.now();
    if (left <= 0) return 'due now';
    const days = left / me.settings.dayMs;
    if (me.settings.dayMs < 86_400_000) return `${days.toFixed(1)} days (${Math.ceil(left / 1000)}s)`;
    return days >= 1 ? `${days.toFixed(1)} days` : `${Math.ceil(left / 3_600_000)} h`;
  }
  function ago(ms) {
    if (!ms) return 'never';
    const s = Math.floor((Date.now() - ms) / 1000);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }
  const isOnline = (d) => d.last_seen && Date.now() - d.last_seen < 20 * 60_000; // agent checks in every 15 min
  const pill = (s, label) => `<span class="state st-${esc(s)}">${esc(label || STATE_LABEL[s] || s)}</span>`;

  // ----- views -----
  function showLogin() {
    me = null;
    $('#app-view').classList.add('hidden');
    $('#login-view').classList.remove('hidden');
  }
  async function showApp() {
    me = await api('/me');
    $('#who').textContent = me.username;
    $('#who-initial').textContent = me.username.slice(0, 1);
    const demo = me.settings.dayMs < 86_400_000;
    $('#mode-badge').textContent = demo ? `DEMO: 1 day = ${me.settings.dayMs / 1000}s` : '';
    $('#mode-badge').classList.toggle('hidden', !demo);
    $('#login-view').classList.add('hidden');
    $('#app-view').classList.remove('hidden');
    await refresh();
  }

  function setTab(tab) {
    currentTab = tab;
    $$('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
    $$('[data-panel]').forEach((p) => p.classList.toggle('hidden', p.dataset.panel !== tab));
    $('#page-title').textContent = TITLES[tab];
    closeMenu();
    refresh();
  }

  async function refresh() {
    if (!me) return;
    try {
      if (currentTab === 'overview') {
        lastDevices = await api('/devices');
        renderOverview(lastDevices);
      }
      if (currentTab === 'devices') { employees = await api('/employees'); renderDevices(lastDevices = await api('/devices')); }
      if (currentTab === 'employees') { employees = await api('/employees'); renderEmployees(); }
      if (currentTab === 'audit') renderAudit(lastAudit = await api('/audit?limit=500'));
    } catch (e) { /* shown via 401 handler */ }
  }

  // ----- overview -----
  function attentionItems(devices) {
    const items = [];
    for (const d of devices) {
      const name = d.employee_name ? ` · ${d.employee_name}` : '';
      if (d.last_command === 'lock:failed') items.push({ sev: 'crit', t: `Lock failed: ${d.serial}`, d: `The laptop could not be locked${name}. Check the audit log.` });
      if (d.state !== 'WIPED' && !d.key_escrowed) items.push({ sev: 'crit', t: `No recovery key: ${d.serial}`, d: `Locking is blocked until the agent saves the key${name}.` });
      else if (d.state !== 'WIPED' && !d.key_in_sync) items.push({ sev: 'warn', t: `Key out of sync: ${d.serial}`, d: `Waiting for the agent to save the current key${name}.` });
      if (d.state === 'WIPE_PENDING') items.push({ sev: 'crit', t: `Wipe waiting for approval: ${d.serial}`, d: `${d.wipe_approvals}/${me.settings.requiredWipeApprovals} approvals${name}.` });
      if (d.state === 'LOCKED') items.push({ sev: 'warn', t: `Locked, not returned: ${d.serial}`, d: `Wipe approval in ${fmtLeft(d.wipe_due_at)}${name}.` });
      if (d.state === 'GRACE' && d.grace_ends_at - Date.now() < 3 * me.settings.dayMs) items.push({ sev: 'warn', t: `Locks soon: ${d.serial}`, d: `Grace period ends in ${fmtLeft(d.grace_ends_at)}${name}.` });
      if (['ACTIVE', 'OFFBOARDING', 'GRACE'].includes(d.state) && d.last_seen && Date.now() - d.last_seen > 3 * 86_400_000) {
        items.push({ sev: 'info', t: `Offline for ${ago(d.last_seen).replace(' ago', '')}: ${d.serial}`, d: `Locks itself after ${me.settings.leaseDays} days offline${name}.` });
      }
    }
    const order = { crit: 0, warn: 1, info: 2 };
    return items.sort((a, b) => order[a.sev] - order[b.sev]);
  }

  function renderOverview(devices) {
    const count = (s) => devices.filter((d) => d.state === s).length;
    const online = devices.filter(isOnline).length;
    const items = attentionItems(devices);
    const kpis = [
      { label: 'Total laptops', value: devices.length, sub: `${online} online now`, tab: 'devices', filter: 'ALL' },
      { label: 'Active', value: count('ACTIVE'), sub: 'in normal use', tab: 'devices', filter: 'ACTIVE' },
      { label: 'Offboarding / grace', value: count('OFFBOARDING') + count('GRACE'), sub: 'employee leaving', tab: 'devices', filter: 'GRACE' },
      { label: 'Locked', value: count('LOCKED'), sub: 'not returned', tab: 'devices', filter: 'LOCKED', alert: count('LOCKED') > 0 },
      { label: 'Wipe pending', value: count('WIPE_PENDING'), sub: 'needs 2 approvals', tab: 'devices', filter: 'WIPE_PENDING', alert: count('WIPE_PENDING') > 0 },
      { label: 'Needs attention', value: items.length, sub: items.length ? 'see list below' : 'all clear', tab: 'overview', alert: items.some((i) => i.sev === 'crit') },
    ];
    $('#kpis').innerHTML = kpis.map((k) => `<button class="kpi ${k.alert ? 'alert' : ''}" data-goto="${k.tab}" data-filter="${k.filter || ''}">
        <span class="k-label">${esc(k.label)}</span><span class="k-value">${k.value}</span><span class="k-sub">${esc(k.sub)}</span></button>`).join('');

    // Laptops by state: horizontal bar chart (one hue; the state name labels each bar).
    $('#state-total').textContent = `${devices.length} laptop${devices.length === 1 ? '' : 's'}`;
    if (!devices.length) {
      $('#state-chart').innerHTML = '<div class="empty">No laptops enrolled yet. Go to <b>Enroll laptops</b> to add the first one.</div>';
    } else {
      const max = Math.max(1, ...STATES.map(count));
      const W = Math.max(300, Math.round($('#state-chart').clientWidth || 520)), labelW = 110, valW = 36, rowH = 34, barH = 14;
      const plotW = W - labelW - valW;
      const rows = STATES.map((s, i) => {
        const n = count(s);
        const y = i * rowH;
        const w = n ? Math.max(4, (n / max) * plotW) : 0;
        const pct = devices.length ? Math.round((n / devices.length) * 100) : 0;
        return `<g class="row" data-goto="devices" data-filter="${s}">
          <title>${esc(STATE_LABEL[s])}: ${n} laptop${n === 1 ? '' : 's'} (${pct}%)</title>
          <rect class="hit" x="0" y="${y}" width="${W}" height="${rowH}"/>
          <text class="lbl" x="0" y="${y + rowH / 2 + 4}">${esc(STATE_LABEL[s])}</text>
          ${w ? `<rect class="bar" x="${labelW}" y="${y + (rowH - barH) / 2}" width="${w.toFixed(1)}" height="${barH}" rx="4"/>` : ''}
          <text class="val" x="${labelW + w + 8}" y="${y + rowH / 2 + 4}">${n}</text></g>`;
      }).join('');
      $('#state-chart').innerHTML = `<svg viewBox="0 0 ${W} ${STATES.length * rowH}" role="img" aria-label="Laptops by state">
        <line class="base" x1="${labelW}" y1="0" x2="${labelW}" y2="${STATES.length * rowH}"/>${rows}</svg>`;
    }

    $('#attn-count').textContent = items.length ? `${items.length} item${items.length === 1 ? '' : 's'}` : '';
    $('#attention').innerHTML = items.length
      ? items.slice(0, 8).map((i) => `<li><span class="attn-icon ${i.sev}">${i.sev === 'info' ? 'i' : '!'}</span>
          <div><div class="t">${esc(i.t)}</div><div class="d">${esc(i.d)}</div></div></li>`).join('')
      : '<li class="attn-ok">✓ Nothing needs attention right now.</li>';
  }

  // ----- devices -----
  function timerFor(d) {
    switch (d.state) {
      case 'GRACE': return `Locks in <b>${fmtLeft(d.grace_ends_at)}</b>`;
      case 'LOCKED': {
        const status = d.lock_confirmed_at ? 'Lock confirmed'
          : d.last_command === 'lock:failed' ? '<b class="warn">⚠ Lock FAILED on laptop. See audit log.</b>'
          : 'Lock sent, waiting for laptop';
        return `${status}<div class="sub">Wipe approval in ${fmtLeft(d.wipe_due_at)}</div>`;
      }
      case 'WIPE_PENDING': return `Approvals <b>${d.wipe_approvals}/${me.settings.requiredWipeApprovals}</b><div class="sub">${esc(d.approved_by || 'none yet')}</div>`;
      case 'OFFBOARDING': return 'Employee serving notice';
      default: return '<span class="muted">—</span>';
    }
  }

  function actionsFor(d) {
    const b = (act, label, cls = '') => `<button class="btn sm ${cls}" data-act="${act}" data-id="${d.id}">${label}</button>`;
    const out = [];
    if (['ACTIVE', 'RETURNED'].includes(d.state)) out.push(b('assign', 'Assign'));
    if (['ACTIVE', 'OFFBOARDING', 'GRACE'].includes(d.state)) out.push(b('lock', 'Lock now', 'danger'));
    if (['LOCKED', 'WIPE_PENDING'].includes(d.state)) out.push(b('cancel-lock', 'Cancel lock'));
    if (d.state === 'LOCKED') out.push(b('request-wipe', 'Request wipe', 'danger'));
    if (d.state === 'WIPE_PENDING') out.push(b('approve-wipe', 'Approve wipe', 'danger'));
    if (!['ACTIVE', 'RETURNED'].includes(d.state)) out.push(b('returned', 'Mark returned'));
    if (d.key_escrowed) out.push(b('recovery-key', 'Recovery key'));
    if (d.state !== 'WIPED') out.push(b('allow-reenroll', 'Allow re-enroll', 'subtle'));
    return `<div class="actions">${out.join('')}</div>`;
  }

  function renderDevFilters(devices) {
    const count = (s) => (s === 'ALL' ? devices.length : devices.filter((d) => d.state === s).length);
    $('#dev-filters').innerHTML = ['ALL', ...STATES].map((s) => `<button class="chip ${devFilter === s ? 'on' : ''}" data-filter-chip="${s}">
      ${s === 'ALL' ? 'All' : esc(STATE_LABEL[s])}<span class="n">${count(s)}</span></button>`).join('');
  }

  function renderDevices(devices) {
    renderDevFilters(devices);
    const qs = $('#dev-search').value.trim().toLowerCase();
    const list = devices.filter((d) => (devFilter === 'ALL' || d.state === devFilter)
      && (!qs || [d.serial, d.hostname, d.employee_name, d.emp_code].some((v) => String(v || '').toLowerCase().includes(qs))));
    $('#devices-body').innerHTML = list.length ? list.map((d) => {
      let report = {};
      try { report = JSON.parse(d.last_report || '{}') || {}; } catch { /* ignore */ }
      const keyLine = !d.key_escrowed ? '<b class="warn">⚠ no key saved</b>'
        : d.key_in_sync ? 'key saved ✓' : '<b class="warn">⚠ key out of sync</b>';
      return `<tr>
        <td data-label="Laptop"><div><b class="mono">${esc(d.serial)}</b><div class="sub">${esc(d.hostname)} · ${esc(d.os)}</div></div></td>
        <td data-label="Assigned to">${d.employee_name ? `<div>${esc(d.employee_name)}<div class="sub">${esc(d.emp_code)}</div></div>` : '<span class="muted">Unassigned</span>'}</td>
        <td data-label="State"><div>${pill(d.state)}<div class="sub">${keyLine}</div></div></td>
        <td data-label="Timer"><div>${timerFor(d)}</div></td>
        <td data-label="Agent"><div><span class="dot ${isOnline(d) ? 'on' : ''}"></span>${ago(d.last_seen)}
            <div class="sub">${report.dryRun ? 'dry-run · ' : ''}${esc(d.last_command || '')}</div></div></td>
        <td data-label="Actions" class="full">${actionsFor(d)}</td></tr>`;
    }).join('') : `<tr><td colspan="6" class="full empty">${devices.length ? 'No laptops match this search or filter.' : 'No laptops enrolled yet. See "Enroll laptops".'}</td></tr>`;
  }

  // ----- employees -----
  function renderEmployees() {
    const qs = $('#emp-search').value.trim().toLowerCase();
    const list = employees.filter((e) => !qs || [e.emp_code, e.name, e.email].some((v) => String(v || '').toLowerCase().includes(qs)));
    const empPill = (s) => pill(s === 'ACTIVE' ? 'ACTIVE' : s === 'LEFT' ? 'LEFT' : 'OFFBOARDING', s === 'LEFT' ? 'Left' : s === 'ACTIVE' ? 'Active' : 'Offboarding');
    $('#employees-body').innerHTML = list.length ? list.map((e) => `<tr>
      <td data-label="Code" class="mono">${esc(e.emp_code)}</td>
      <td data-label="Name"><div>${esc(e.name)}<div class="sub">${esc(e.email)}</div></div></td>
      <td data-label="Status">${empPill(e.status)}</td>
      <td data-label="Last day">${fmtDate(e.last_day)}</td>
      <td data-label="Laptops">${e.device_count}</td>
      <td data-label="Action" class="full">${e.status === 'ACTIVE'
        ? `<button class="btn sm danger" data-act="offboard" data-emp="${e.id}">Start offboarding</button>`
        : `<button class="btn sm" data-act="cancel-offboard" data-emp="${e.id}">Cancel exit</button>`}</td>
    </tr>`).join('') : `<tr><td colspan="6" class="full empty">${employees.length ? 'No employees match this search.' : 'No employees yet. Add one above.'}</td></tr>`;
  }

  // ----- audit -----
  function renderAudit(rows) {
    const qs = $('#audit-search').value.trim().toLowerCase();
    const list = rows.filter((a) => !qs || [a.action, actionLabel(a.action), a.actor, a.serial, a.employee_name, a.details]
      .some((v) => String(v || '').toLowerCase().includes(qs)));
    $('#audit-body').innerHTML = list.length ? list.map((a) => `<tr>
      <td data-label="Time">${fmtTime(a.ts)}</td>
      <td data-label="Actor" class="mono small">${esc(a.actor)}</td>
      <td data-label="Action"><div><b>${esc(actionLabel(a.action))}</b><div class="sub mono">${esc(a.action)}</div></div></td>
      <td data-label="Laptop" class="mono small">${esc(a.serial)}</td>
      <td data-label="Employee">${esc(a.employee_name)}</td>
      <td data-label="Details" class="details">${esc(a.details)}</td></tr>`).join('')
      : '<tr><td colspan="6" class="full empty">No matching entries.</td></tr>';
  }

  // ----- mobile menu -----
  function openMenu() { $('#sidebar').classList.add('open'); $('#scrim').classList.remove('hidden'); }
  function closeMenu() { $('#sidebar').classList.remove('open'); $('#scrim').classList.add('hidden'); }
  $('#menu-btn').addEventListener('click', openMenu);
  $('#scrim').addEventListener('click', closeMenu);

  // ----- events -----
  $('#login-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    $('#login-error').textContent = '';
    const fd = new FormData(ev.target);
    try {
      await api('/login', { body: { username: fd.get('username'), password: fd.get('password') } });
      ev.target.reset();
      await showApp();
    } catch (e) { $('#login-error').textContent = e.message; }
  });

  $('#logout').addEventListener('click', async () => {
    await api('/logout', { body: {} }).catch(() => {});
    showLogin();
  });

  $('#tabs').addEventListener('click', (ev) => {
    const t = ev.target.closest('[data-tab]');
    if (t) setTab(t.dataset.tab);
  });

  $('#dev-search').addEventListener('input', () => renderDevices(lastDevices));
  $('#emp-search').addEventListener('input', renderEmployees);
  $('#audit-search').addEventListener('input', () => renderAudit(lastAudit));

  $('#emp-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const fd = Object.fromEntries(new FormData(ev.target));
    try { await api('/employees', { body: fd }); ev.target.reset(); flash('Employee added'); refresh(); }
    catch (e) { flash(e.message, false); }
  });

  $('#token-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const fd = Object.fromEntries(new FormData(ev.target));
    try {
      const r = await api('/enroll-token', { body: fd });
      const out = $('#token-out');
      out.textContent = `Save this as config.json next to killswitch-agent.exe:\n\n${JSON.stringify(r.agentConfig, null, 2)}\n\nToken works for ${r.uses} laptop(s) for ${r.hours} hour(s). dryRun=true only logs actions; set it to false to really lock/wipe.`;
      out.classList.remove('hidden');
    } catch (e) { flash(e.message, false); }
  });

  $('#hr-info').addEventListener('click', async () => {
    try {
      const r = await api('/hr-webhook-info');
      const out = $('#hr-out');
      out.textContent = `URL:    ${r.url}\nSecret: ${r.secret}\n\nExample bodies:\n{"event":"employee.exit","empCode":"E101","lastWorkingDay":"2026-12-15"}\n{"event":"employee.exit_cancelled","empCode":"E101"}`;
      out.classList.remove('hidden');
    } catch (e) { flash(e.message, false); }
  });

  document.addEventListener('click', async (ev) => {
    // navigation shortcuts (KPI tiles, chart rows, "View audit log")
    const go = ev.target.closest('[data-goto]');
    if (go) {
      if (go.dataset.filter) devFilter = go.dataset.filter;
      if (go.dataset.goto !== currentTab) setTab(go.dataset.goto);
      return;
    }
    const chip = ev.target.closest('[data-filter-chip]');
    if (chip) { devFilter = chip.dataset.filterChip; renderDevices(lastDevices); return; }

    const btn = ev.target.closest('[data-act]');
    if (!btn) return;
    const act = btn.dataset.act;
    const id = btn.dataset.id;
    try {
      if (act === 'offboard') {
        const demo = me.settings.dayMs < 86_400_000;
        const fd = await dialog('Start offboarding',
          demo
            ? `<label>Last working day is in how many (demo) days?<input name="lastDayInDays" type="number" value="1" min="0" step="0.5"></label>`
            : `<p>The employee's laptops lock ${me.settings.graceDays} days after the last working day unless they are returned.</p><label>Last working day<input name="lastWorkingDay" type="date" required></label>`,
          'Start offboarding', true);
        if (!fd) return;
        await api(`/employees/${btn.dataset.emp}/offboard`, { body: Object.fromEntries(fd) });
        flash(`Offboarding started. Laptops lock ${me.settings.graceDays} days after the last working day unless returned.`);
      } else if (act === 'cancel-offboard') {
        if (!await dialog('Cancel this exit?', '<p>Use this when the employee is staying. Their laptops go back to normal. If a laptop was already locked, enter its recovery key at the BitLocker screen; the agent then restores it automatically.</p>', 'Cancel exit')) return;
        await api(`/employees/${btn.dataset.emp}/cancel-offboarding`, { body: {} });
        flash('Exit cancelled. Laptops are back to normal.');
      } else if (act === 'allow-reenroll') {
        if (!await dialog('Allow re-enrollment?', '<p>Only do this if this laptop was reinstalled or its agent was set up again. For the next 24 hours, the laptop can register again with an enrollment token. A missing laptop that re-enrolls keeps its state and is locked again.</p>', 'Allow for 24 h', true)) return;
        await api(`/devices/${id}/allow-reenroll`, { body: {} });
        flash('Re-enrollment allowed for 24 hours');
      } else if (act === 'assign') {
        const opts = employees.filter((e) => e.status === 'ACTIVE').map((e) => `<option value="${e.id}">${esc(e.name)} (${esc(e.emp_code)})</option>`).join('');
        const fd = await dialog('Assign laptop', `<label>Employee<select name="employeeId"><option value="">— Unassigned —</option>${opts}</select></label>`, 'Assign');
        if (!fd) return;
        await api(`/devices/${id}/assign`, { body: { employeeId: fd.get('employeeId') } });
        flash('Laptop assigned');
      } else if (act === 'lock') {
        const dev = lastDevices.find((x) => String(x.id) === String(id));
        const warn = dev && !dev.key_in_sync
          ? '<p class="warn"><b>⚠ Warning:</b> the recovery key on the server does not match the laptop yet. The agent will refuse to lock until the key is synced. Wait for the next check-in first.</p>' : '';
        if (!await dialog('Lock this laptop now?', `<p>The laptop reboots to the BitLocker recovery screen the next time it checks in. This can be undone with the recovery key.</p>${warn}`, 'Lock now', true)) return;
        await api(`/devices/${id}/lock`, { body: { reason: 'manual lock from dashboard' } });
        flash('Lock ordered');
      } else if (act === 'cancel-lock') {
        await api(`/devices/${id}/cancel-lock`, { body: {} });
        flash('Lock cancelled');
      } else if (act === 'request-wipe') {
        if (!await dialog('Request wipe?', `<p>This sends the laptop for wipe approval. ${me.settings.requiredWipeApprovals} different admins must approve.</p>`, 'Request wipe', true)) return;
        await api(`/devices/${id}/request-wipe`, { body: {} });
        flash('Wipe requested. Waiting for approvals.');
      } else if (act === 'approve-wipe') {
        if (!await dialog('Approve PERMANENT wipe?', '<p><b>This cannot be undone.</b> When enough admins approve, the saved recovery key is destroyed and the laptop is factory-reset. All data on it becomes unrecoverable.</p><p>If data theft is suspected, recover the laptop and image the disk first.</p>', 'Approve wipe', true)) return;
        const d = await api(`/devices/${id}/approve-wipe`, { body: {} });
        flash(d.state === 'WIPED' ? 'Wipe executed' : 'Approval recorded. Another admin must approve.');
      } else if (act === 'returned') {
        if (!await dialog('Mark laptop as returned?', '<p>Cancels any pending lock or wipe. If the laptop is locked, use "Recovery key" to unlock it at the BitLocker screen.</p>', 'Mark returned')) return;
        await api(`/devices/${id}/returned`, { body: {} });
        flash('Laptop marked as returned');
      } else if (act === 'recovery-key') {
        if (!await dialog('Reveal recovery key?', '<p>This is recorded in the audit log.</p>', 'Reveal')) return;
        const r = await api(`/devices/${id}/recovery-key`, { body: {} });
        await dialog('BitLocker recovery key', `<div class="big-key">${esc(r.recoveryKey)}</div>`, 'Done');
      }
      refresh();
    } catch (e) { flash(e.message, false); }
  });

  // Refresh data in the background, but never while a dialog is open or the user is typing in a form.
  setInterval(() => {
    if ($('#dialog').open) return;
    const a = document.activeElement;
    if (a && a.closest && a.closest('form')) return;
    refresh();
  }, 5000);
  api('/me').then(showApp).catch(showLogin);
})();
