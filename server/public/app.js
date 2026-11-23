'use strict';
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  let me = null;
  let employees = [];
  let currentTab = 'devices';

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
      ok.className = `btn ${danger ? 'danger' : 'primary'}`;
      d.onclose = () => resolve(d.returnValue === 'ok' ? new FormData($('.dialog-body')) : null);
      d.showModal();
    });
  }

  // ----- time helpers -----
  const fmtTime = (ms) => (ms ? new Date(ms).toLocaleString() : '—');
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

  // ----- views -----
  function showLogin() {
    $('#app-view').classList.add('hidden');
    $('#login-view').classList.remove('hidden');
  }
  async function showApp() {
    me = await api('/me');
    $('#who').textContent = me.username;
    $('#mode-badge').textContent = me.settings.dayMs < 86_400_000 ? `DEMO: 1 day = ${me.settings.dayMs / 1000}s` : '';
    $('#mode-badge').classList.toggle('hidden', me.settings.dayMs >= 86_400_000);
    $('#login-view').classList.add('hidden');
    $('#app-view').classList.remove('hidden');
    await refresh();
  }

  async function refresh() {
    if (!me) return;
    try {
      employees = await api('/employees');
      if (currentTab === 'devices') renderDevices(await api('/devices'));
      if (currentTab === 'employees') renderEmployees();
      if (currentTab === 'audit') renderAudit(await api('/audit'));
    } catch (e) { /* shown via 401 handler */ }
  }

  function timerFor(d) {
    switch (d.state) {
      case 'GRACE': return `Locks in <b>${fmtLeft(d.grace_ends_at)}</b>`;
      case 'LOCKED': return `${d.lock_confirmed_at ? 'Lock confirmed' : 'Lock sent, waiting for laptop'}<div class="sub">Wipe approval in ${fmtLeft(d.wipe_due_at)}</div>`;
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
    return `<div class="actions">${out.join('')}</div>`;
  }

  function renderDevices(devices) {
    const count = (s) => devices.filter((d) => d.state === s).length;
    $('#stats').innerHTML = ['ACTIVE', 'OFFBOARDING', 'GRACE', 'LOCKED', 'WIPE_PENDING', 'WIPED', 'RETURNED']
      .map((s) => `<div class="stat"><b>${count(s)}</b><span class="state st-${s}">${s.replace('_', ' ')}</span></div>`).join('');
    $('#devices-body').innerHTML = devices.length ? devices.map((d) => {
      let report = {};
      try { report = JSON.parse(d.last_report || '{}') || {}; } catch { /* ignore */ }
      const online = d.last_seen && Date.now() - d.last_seen < 5 * 60_000;
      return `<tr>
        <td><b class="mono">${esc(d.serial)}</b><div class="sub">${esc(d.hostname)} · ${esc(d.os)}</div></td>
        <td>${d.employee_name ? `${esc(d.employee_name)}<div class="sub">${esc(d.emp_code)}</div>` : '<span class="muted">Unassigned</span>'}</td>
        <td><span class="state st-${esc(d.state)}">${esc(d.state.replace('_', ' '))}</span>
            <div class="sub">${d.key_escrowed ? 'key escrowed' : 'no key escrowed'}</div></td>
        <td>${timerFor(d)}</td>
        <td>${online ? '🟢' : '⚪'} ${ago(d.last_seen)}
            <div class="sub">${report.dryRun ? 'dry-run · ' : ''}${esc(d.last_command || '')}</div></td>
        <td>${actionsFor(d)}</td></tr>`;
    }).join('') : '<tr><td colspan="6" class="muted">No laptops enrolled yet — see "Enroll laptops".</td></tr>';
  }

  function renderEmployees() {
    $('#employees-body').innerHTML = employees.length ? employees.map((e) => `<tr>
      <td class="mono">${esc(e.emp_code)}</td><td>${esc(e.name)}<div class="sub">${esc(e.email)}</div></td>
      <td><span class="state st-${e.status === 'ACTIVE' ? 'ACTIVE' : e.status === 'LEFT' ? 'LEFT' : 'OFFBOARDING'}">${esc(e.status)}</span></td>
      <td>${fmtTime(e.last_day)}</td><td>${e.device_count}</td>
      <td>${e.status === 'ACTIVE' ? `<button class="btn sm danger" data-act="offboard" data-emp="${e.id}">Start offboarding</button>` : ''}</td>
    </tr>`).join('') : '<tr><td colspan="6" class="muted">No employees yet.</td></tr>';
  }

  function renderAudit(rows) {
    $('#audit-body').innerHTML = rows.map((a) => `<tr>
      <td>${fmtTime(a.ts)}</td><td class="mono small">${esc(a.actor)}</td><td><b>${esc(a.action)}</b></td>
      <td class="mono small">${esc(a.serial)}</td><td>${esc(a.employee_name)}</td>
      <td class="details mono">${esc(a.details)}</td></tr>`).join('');
  }

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
    me = null;
    showLogin();
  });

  $('#tabs').addEventListener('click', (ev) => {
    const t = ev.target.closest('[data-tab]');
    if (!t) return;
    currentTab = t.dataset.tab;
    $$('.tab').forEach((b) => b.classList.toggle('active', b === t));
    $$('[data-panel]').forEach((p) => p.classList.toggle('hidden', p.dataset.panel !== currentTab));
    refresh();
  });

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
      out.textContent = `URL:    ${r.url}\nSecret: ${r.secret}\n\nExample body:\n{"event":"employee.exit","empCode":"E101","lastWorkingDay":"2026-12-15"}`;
      out.classList.remove('hidden');
    } catch (e) { flash(e.message, false); }
  });

  document.addEventListener('click', async (ev) => {
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
            : `<label>Last working day<input name="lastWorkingDay" type="date" required></label>`,
          'Start offboarding', true);
        if (!fd) return;
        await api(`/employees/${btn.dataset.emp}/offboard`, { body: Object.fromEntries(fd) });
        flash(`Offboarding started. Laptops lock ${me.settings.graceDays} days after the last working day unless returned.`);
      } else if (act === 'assign') {
        const opts = employees.filter((e) => e.status === 'ACTIVE').map((e) => `<option value="${e.id}">${esc(e.name)} (${esc(e.emp_code)})</option>`).join('');
        const fd = await dialog('Assign laptop', `<label>Employee<select name="employeeId"><option value="">— Unassigned —</option>${opts}</select></label>`, 'Assign');
        if (!fd) return;
        await api(`/devices/${id}/assign`, { body: { employeeId: fd.get('employeeId') } });
        flash('Laptop assigned');
      } else if (act === 'lock') {
        if (!await dialog('Lock this laptop now?', '<p>The laptop will reboot to the BitLocker recovery screen the next time it checks in. This can be undone with the recovery key.</p>', 'Lock now', true)) return;
        await api(`/devices/${id}/lock`, { body: { reason: 'manual lock from dashboard' } });
        flash('Lock ordered');
      } else if (act === 'cancel-lock') {
        await api(`/devices/${id}/cancel-lock`, { body: {} });
        flash('Lock cancelled');
      } else if (act === 'request-wipe') {
        if (!await dialog('Request wipe?', `<p>This sends the laptop for wipe approval. ${me.settings.requiredWipeApprovals} different admins must approve.</p>`, 'Request wipe', true)) return;
        await api(`/devices/${id}/request-wipe`, { body: {} });
        flash('Wipe requested — waiting for approvals');
      } else if (act === 'approve-wipe') {
        if (!await dialog('Approve PERMANENT wipe?', '<p><b>This cannot be undone.</b> When enough admins approve, the escrowed recovery key is destroyed and the laptop is factory-reset. All data on it becomes unrecoverable.</p><p>If data theft is suspected, recover the laptop and image the disk first.</p>', 'Approve wipe', true)) return;
        const d = await api(`/devices/${id}/approve-wipe`, { body: {} });
        flash(d.state === 'WIPED' ? 'Wipe executed' : 'Approval recorded — another admin must approve');
      } else if (act === 'returned') {
        if (!await dialog('Mark laptop as returned?', '<p>Cancels any pending lock or wipe. If the laptop is locked, use "Recovery key" to unlock it at the BitLocker screen.</p>', 'Mark returned')) return;
        await api(`/devices/${id}/returned`, { body: {} });
        flash('Laptop marked as returned');
      } else if (act === 'recovery-key') {
        if (!await dialog('Reveal recovery key?', '<p>This is recorded in the audit log.</p>', 'Reveal')) return;
        const r = await api(`/devices/${id}/recovery-key`, { body: {} });
        await dialog('BitLocker recovery key', `<div class="big-key mono">${esc(r.recoveryKey)}</div>`, 'Done');
      }
      refresh();
    } catch (e) { flash(e.message, false); }
  });

  setInterval(refresh, 3000);
  api('/me').then(showApp).catch(showLogin);
})();
