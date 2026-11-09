// Batch-2 UI/API coverage: executions view, backup global settings,
// setup status, audit persistence signal, self-password prompt path.
import { ensureService, sleep } from '../lib/harness.mjs';

export default async function run(h) {
  const ctx = h.ctx;
  const { page } = h;
  await ensureService(h);

  // --- Executions view -------------------------------------------------
  await h.goto('/executions');
  await sleep(1200);
  const execText = await h.compText('ddm-executions');
  ctx.check('executions: view renders rows', /executions/i.test(execText) && execText.length > 50, execText.slice(0, 80));

  // click first row → detail card with output area appears
  const clicked = await page.evaluate(() => {
    const c = window.__deep('ddm-executions');
    const row = c?.shadowRoot?.querySelector('tbody tr');
    if (row) { row.click(); return true; }
    return false;
  });
  if (clicked) {
    await sleep(1500);
    const detail = await h.compText('ddm-executions');
    ctx.check('executions: row opens detail/output', /finished|running|no output/i.test(detail), detail.slice(-120));
  } else {
    ctx.check('executions: row opens detail/output', false, 'no rows to click');
  }

  // --- Backup global settings -----------------------------------------
  await h.goto('/service/e2e-svc');
  await h.tab('Backup');
  await sleep(800);
  const hasGlobal = await page.evaluate(() => {
    const c = window.__deep('ddm-backup-panel');
    const s = c?.shadowRoot?.querySelector('summary');
    const found = [...(c?.shadowRoot?.querySelectorAll('summary') ?? [])]
      .find(x => x.textContent.toLowerCase().includes('global backup settings'));
    if (found) { found.click(); return true; }
    return false;
  });
  ctx.check('backup: global settings section present (admin)', hasGlobal);
  if (hasGlobal) {
    await sleep(800);
    // open the editor and verify the structured form renders
    await page.evaluate(() => window.__clickIn('ddm-backup-panel', 'edit global settings'));
    await sleep(800);
    const formText = await h.compText('ddm-backup-panel');
    ctx.check('backup global: form renders scheduler+retention',
      /systemd timer|on_calendar|keep/i.test(formText), formText.slice(0, 60));
    const g = await h.api('/api/backup/global');
    ctx.check('backup global: GET returns config', g.status === 200 && 'enabled' in g.data, JSON.stringify(g.data).slice(0, 100));

    // round-trip: set keep_last=3 then restore
    const orig = g.data;
    const put = await h.api('/api/backup/global', {
      method: 'PUT',
      body: {
        enabled: orig.enabled,
        scheduler: orig.scheduler ?? 'systemd_timer',
        on_calendar: orig.on_calendar ?? '',
        excludes: orig.excludes ?? [],
        retention: { keep_last: 3, keep_daily: null, keep_weekly: null, keep_monthly: null },
      },
    });
    ctx.check('backup global: PUT keep_last=3', put.status === 200, `status=${put.status} ${JSON.stringify(put.data).slice(0, 80)}`);
    const after = await h.api('/api/backup/global');
    ctx.check('backup global: retention persisted', after.data?.retention?.keep_last === 3, `keep_last=${after.data?.retention?.keep_last}`);
    // restore original retention
    await h.api('/api/backup/global', {
      method: 'PUT',
      body: {
        enabled: orig.enabled,
        scheduler: orig.scheduler ?? 'systemd_timer',
        on_calendar: orig.on_calendar ?? '',
        excludes: orig.excludes ?? [],
        retention: orig.retention ?? { keep_last: null, keep_daily: null, keep_weekly: null, keep_monthly: null },
      },
    });
    // unknown key must be rejected
    const bad = await h.api('/api/backup/global', { method: 'PUT', body: { bogus_key: 1 } });
    ctx.check('backup global: unknown key rejected', bad.status === 400 || bad.status === 422, `status=${bad.status}`);
  }

  // --- Setup endpoint ---------------------------------------------------
  const setup = await h.api('/api/setup');
  ctx.check('setup: status endpoint responds', setup.status === 200, `status=${setup.status} needed=${setup.data?.needed}`);
  ctx.check('setup: closed after users exist', setup.data?.needed === false, `needed=${setup.data?.needed}`);
  // unauthenticated POST must also fail once users exist
  const unauth = await page.evaluate(async () => {
    const r = await fetch('/api/setup', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'x', password: 'x' }),
    });
    return r.status;
  });
  ctx.check('setup: POST rejected when users exist', unauth === 403 || unauth === 409 || unauth === 400, `status=${unauth}`);

  // --- Audit persistence signal ----------------------------------------
  const audit = await h.api('/api/audit?limit=5');
  const entries = Array.isArray(audit.data) ? audit.data : (audit.data?.entries ?? []);
  ctx.check('audit: entries recorded', entries.length > 0, `${entries.length} entries`);
  if (entries.length) {
    const e = entries[0];
    ctx.check('audit: entry shape', !!e.at && !!e.action && !!e.user, `${e.action} by ${e.user}`);
  }

  // --- Executions API scope ---------------------------------------------
  const ex = await h.api('/api/executions');
  const list = Array.isArray(ex.data) ? ex.data : [];
  ctx.check('executions: API list non-empty', list.length > 0, `${list.length} executions`);
  if (list.length) {
    const d = await h.api(`/api/executions/${list[0].id}`);
    ctx.check('executions: detail endpoint', d.status === 200, `status=${d.status}`);
  }
}
