import { CONFIG, sleep } from '../lib/harness.mjs';

export default async function (h) {
  const { ctx, page } = h;
  const svc = CONFIG.svc;
  await h.goto(`/service/${svc}`);
  await sleep(1000);

  // ---- unit editor ----
  await h.tab('Unit');
  for (const [label, wait] of [['check', 3000], ['regenerate', 3000], ['save', 3000], ['save & restart', 4000]]) {
    const ok = await page.evaluate((t) => window.__clickText(t), label);
    ctx.check(`unit: ${label} button`, ok === true);
    await sleep(wait);
  }

  // ---- backup panel ----
  await h.tab('Backup');
  // open config editor and save as-is
  let r = await page.evaluate(async () => {
    const bp = window.__deep('ddm-backup-panel');
    const cfgBtn = [...bp.shadowRoot.querySelectorAll('button')].find(b => b.textContent.trim() === 'config');
    if (cfgBtn) cfgBtn.click();
    await new Promise(r => setTimeout(r, 700));
    const saveBtn = [...bp.shadowRoot.querySelectorAll('button')].find(b => b.textContent.trim() === 'save' && b.offsetParent);
    if (saveBtn) saveBtn.click();
    await new Promise(r => setTimeout(r, 1500));
    return { ok: !!saveBtn };
  });
  ctx.check('backup: config save', r.ok === true);

  for (const [label, wait] of [['provision', 5000], ['run now', 12000], ['snapshots', 3000]]) {
    const ok = await page.evaluate((t) => {
      const bp = window.__deep('ddm-backup-panel');
      const b = [...bp.shadowRoot.querySelectorAll('button')].find(x => x.textContent.trim() === t && x.offsetParent);
      if (b) { b.click(); return true; } return false;
    }, label);
    ctx.check(`backup: ${label} button`, ok === true);
    await sleep(wait);
  }
  // restic run is async — poll for the snapshot to appear
  let snaps = { data: [] };
  for (let i = 0; i < 10; i++) {
    await sleep(4000);
    snaps = await h.api(`/api/services/${svc}/backup/snapshots`);
    if (Array.isArray(snaps.data) && snaps.data.length > 0) break;
  }
  ctx.check('backup: snapshot exists after run', Array.isArray(snaps.data) && snaps.data.length > 0, `api=${JSON.stringify(snaps).slice(0, 160)}`);

  // restore first snapshot to /tmp (prompt for target)
  if (Array.isArray(snaps.data) && snaps.data.length > 0) {
    h.ctx.expectDialog('/tmp/e2e-restore');
    r = await page.evaluate(async () => {
      const bp = window.__deep('ddm-backup-panel');
      const btn = [...bp.shadowRoot.querySelectorAll('button')].find(b => b.textContent.trim() === 'restore');
      if (!btn) return { err: 'no restore btn' };
      btn.click();
      await new Promise(r => setTimeout(r, 4000));
      return { ok: true, msg: bp.shadowRoot.textContent.slice(0, 300) };
    });
    ctx.check('backup: restore button', r.ok === true, (r.msg || r.err || '').slice(0, 100));
  }

  // forget --prune (keep-policy may retain latest; just verify it runs)
  const fg = await page.evaluate(async () => {
    const bp = window.__deep('ddm-backup-panel');
    const b = [...bp.shadowRoot.querySelectorAll('button')].find(x => x.textContent.includes('forget'));
    if (b) { b.click(); await new Promise(r => setTimeout(r, 5000)); return true; } return false;
  });
  ctx.check('backup: forget --prune button', fg === true);
}
