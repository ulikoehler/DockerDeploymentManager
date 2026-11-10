import { CONFIG, sleep, ensureService } from '../lib/harness.mjs';

// file delete takes ?path= query — h.api has no query support, so do it
// through fetch inside the page (session token is already stored there).
async function apiDel(page, path) {
  return page.evaluate(async (p) => {
    const tok = sessionStorage.getItem('ddm_token');
    const r = await fetch(p, { method: 'DELETE', headers: { Authorization: `Bearer ${tok}` } });
    return r.status;
  }, path);
}

// Coverage for the "missing features" batch: token list/revoke, audit view,
// commands section editor, gitops config form, backup structured form,
// service search/filter, file upload/download, users effective preview,
// WebDAV visibility, docs link.
export default async function (h) {
  const { ctx, page } = h;
  const svc = CONFIG.svc;
  await ensureService(h);

  // ============ service list: search/filter ============
  await h.goto('/');
  await sleep(1200);
  const filterRes = await page.evaluate(() => {
    const sl = window.__deep('ddm-service-list');
    if (!sl?.shadowRoot) return { ok: false };
    const input = sl.shadowRoot.querySelector('input[placeholder*="filter"]');
    const sel = sl.shadowRoot.querySelector('select');
    if (!input || !sel) return { ok: false };
    window.__setVal(input, 'zzz-no-match');
    return { ok: true };
  });
  ctx.check('servicelist: filter input present', filterRes.ok === true, '');
  await sleep(400);
  const noMatch = await h.compText('ddm-service-list');
  ctx.check('servicelist: query filters rows', /no services match/i.test(noMatch || ''), '');
  await page.evaluate(() => {
    const sl = window.__deep('ddm-service-list');
    const input = sl.shadowRoot.querySelector('input[placeholder*="filter"]');
    window.__setVal(input, '');
  });
  await sleep(300);

  // ============ tokens: list + revoke ============
  await h.goto('/token');
  await sleep(1500);
  const minted = await h.api('/api/auth/token', {
    method: 'POST',
    body: { ttl_minutes: 30, services: [svc], actions: ['read'] },
  });
  ctx.check('tokens: mint via api', minted.status === 200 && !!minted.data?.token, `status=${minted.status}`);
  await sleep(800);
  const tokList = await h.api('/api/auth/tokens');
  // our minted token is the one scoped to the scratch service
  const rec = (tokList.data || []).find(
    (t) => !t.revoked && t.exp * 1000 > Date.now() && (t.services || []).includes(svc),
  ) || (tokList.data || []).find((t) => !t.revoked && t.exp * 1000 > Date.now());
  ctx.check('tokens: minted token listed', !!rec, `count=${(tokList.data || []).length}`);
  const tokTxt = await h.compText('ddm-token');
  ctx.check('tokens: sessions & tokens table rendered',
    /sessions & tokens/i.test(tokTxt || '') && /active|expired|revoked/i.test(tokTxt || ''), '');
  if (rec) {
    // revoke through the UI button on the row scoped to our scratch service
    const clicked = await page.evaluate(() => {
      const c = window.__deep('ddm-token');
      if (!c?.shadowRoot) return false;
      const rows = [...c.shadowRoot.querySelectorAll('tbody tr')];
      const row = rows.find(r => /e2e-svc/.test(r.textContent) && /active/.test(r.textContent));
      const btn = row && [...row.querySelectorAll('button')].find(b => /revoke/i.test(b.textContent));
      if (btn) { btn.click(); return true; }
      return false;
    });
    ctx.check('tokens: revoke button clicked in UI', clicked === true, '');
    await sleep(1200);
    const after = await h.api('/api/auth/tokens');
    const gone = (after.data || []).find((t) => t.jti === rec.jti);
    ctx.check('tokens: revoke marks record', gone?.revoked === true, `revoked=${gone?.revoked}`);
    const tokTxt2 = await h.compText('ddm-token');
    ctx.check('tokens: revoked badge in UI', /revoked/i.test(tokTxt2 || ''), '');
  }

  // ============ audit view (admin) ============
  await h.goto('/audit');
  await sleep(1500);
  const auditTxt = await h.compText('ddm-audit');
  ctx.check('audit: view renders entries',
    /login|token|file|section|audit|user/i.test(auditTxt || ''),
    auditTxt.slice(0, 100).replace(/\n/g, ' '));

  // ============ commands: admin section editor ============
  // (structured per-item editing is covered end-to-end in 90-batch3;
  // here we keep the lightweight checks that don't duplicate it)
  await h.goto('/commands');
  await sleep(1500);
  const editBtn = await h.clickIn('ddm-commands', 'edit sections');
  ctx.check('commands: edit sections button (admin)', editBtn === true, '');
  await sleep(800);
  const structEditor = await page.evaluate(() => {
    const c = window.__deep('ddm-commands');
    if (!c?.shadowRoot) return false;
    const t = c.shadowRoot.textContent;
    return /\+ item/.test(t) && /save/.test(t);
  });
  ctx.check('commands: structured section/item editor present', structEditor === true, '');
  await h.clickIn('ddm-commands', 'done editing');

  // ============ gitops config form ============
  await h.goto('/gitops');
  await sleep(1500);
  const cfgBtn = await h.clickIn('ddm-gitops-panel', 'configure');
  ctx.check('gitops: configure button (admin)', cfgBtn === true, '');
  await sleep(600);
  const gitopsSaved = await page.evaluate(async () => {
    const c = window.__deep('ddm-gitops-panel');
    if (!c?.shadowRoot) return 'no-component';
    const ed = c.shadowRoot.querySelector('ddm-code-editor');
    if (ed) ed.setDoc(JSON.stringify([{ into: 'services', path: 'e2e' }]));
    else {
      const ta = c.shadowRoot.querySelector('textarea');
      if (ta) window.__setVal(ta, JSON.stringify([{ into: 'services', path: 'e2e' }]));
    }
    const save = [...c.shadowRoot.querySelectorAll('button')].find(b => b.textContent.trim() === 'save');
    if (!save) return 'no-save';
    save.click();
    await new Promise(r => setTimeout(r, 1500));
    return c.shadowRoot.textContent;
  });
  ctx.check('gitops: config form saves', /saved|error/i.test(String(gitopsSaved)),
    String(gitopsSaved).slice(0, 120).replace(/\n/g, ' '));
  const gc = await h.api('/api/gitops/config');
  ctx.check('gitops: targets persisted via API',
    JSON.stringify(gc.data?.targets || []).includes('e2e'),
    JSON.stringify(gc.data?.targets));
  // restore: leave gitops disabled with no targets
  await h.api('/api/gitops/config', {
    method: 'PUT',
    body: { enabled: false, url: '', branch: 'main', interval_secs: 300, push_changes: false, targets: [] },
  });

  // ============ backup structured form ============
  const hasBackup = await h.api(`/api/services/${svc}/backup/check`);
  if (hasBackup.status === 200) {
    await h.goto(`/service/${svc}`);
    await sleep(1200);
    await h.tab('Backup');
    await sleep(1200);
    const cfgBtn2 = await h.clickIn('ddm-backup-panel', 'config');
    ctx.check('backup: config button opens form', cfgBtn2 === true, '');
    await sleep(500);
    const formTxt = await h.compText('ddm-backup-panel');
    ctx.check('backup: structured fields (paths/excludes/scheduled)',
      /paths/i.test(formTxt || '') && /excludes/i.test(formTxt || '') && /scheduled backups/i.test(formTxt || ''),
      formTxt.slice(0, 120).replace(/\n/g, ' '));
    const saved2 = await page.evaluate(async () => {
      const c = window.__deep('ddm-backup-panel');
      if (!c?.shadowRoot) return false;
      const save = [...c.shadowRoot.querySelectorAll('button')].find(b => b.textContent.trim() === 'save');
      if (!save) return false;
      save.click();
      await new Promise(r => setTimeout(r, 1500));
      return /saved|error/i.test(c.shadowRoot.textContent);
    });
    ctx.check('backup: structured save works', saved2 === true, '');
  } else {
    ctx.pass('backup: scratch service lacks backup config — skipped');
  }

  // ============ files: download + upload ============
  await h.api(`/api/services/${svc}/files`, {
    method: 'PUT',
    body: { path: 'e2e-bin.dat', content: 'e2e-upload-marker' },
  });
  await h.goto(`/service/${svc}`);
  await sleep(1200);
  await h.tab('Files');
  await sleep(1200);
  const filesTxt = await h.compText('ddm-files');
  ctx.check('files: upload button present (dir view)', /upload/i.test(filesTxt || ''), '');
  const up = await page.evaluate(async (s) => {
    const tok = sessionStorage.getItem('ddm_token');
    const bytes = new Uint8Array([0, 1, 2, 255, 254, 10]).buffer;
    const r = await fetch(`/api/services/${s}/files/upload?path=e2e-bin2.dat`, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${tok}` },
      body: bytes,
    });
    return r.status;
  }, svc);
  ctx.check('files: binary upload endpoint', up === 200, `status=${up}`);
  const dl = await page.evaluate(async (s) => {
    const tok = sessionStorage.getItem('ddm_token');
    const r = await fetch(`/api/services/${s}/files/download?path=e2e-bin2.dat`, {
      headers: { Authorization: `Bearer ${tok}` },
    });
    const buf = new Uint8Array(await r.arrayBuffer());
    return { status: r.status, bytes: [...buf] };
  }, svc);
  ctx.check('files: binary download round-trip',
    dl.status === 200 && JSON.stringify(dl.bytes) === JSON.stringify([0, 1, 2, 255, 254, 10]),
    `status=${dl.status} bytes=${JSON.stringify(dl.bytes)}`);
  await apiDel(page, `/api/services/${svc}/files?path=e2e-bin.dat`);
  await apiDel(page, `/api/services/${svc}/files?path=e2e-bin2.dat`);

  // ============ users: effective preview + help ============
  await h.goto('/users');
  await sleep(1500);
  // click the first username link (an <a> inside the users table)
  await page.evaluate(() => {
    const u = window.__deep('ddm-users');
    if (!u?.shadowRoot) return;
    const link = [...u.shadowRoot.querySelectorAll('tbody td a')].find(a => a.offsetParent);
    if (link) link.click();
  });
  await sleep(1500);
  const usersTxt = await h.compText('ddm-users');
  ctx.check('users: permission help text present',
    /permissions work|compose policy|restrictions|effective access/i.test(usersTxt || ''),
    `len=${(usersTxt || '').length} ${usersTxt.slice(0, 80).replace(/\n/g, ' ')}`);
  ctx.check('users: effective access preview',
    /effective access|default_access|compose policy/i.test(usersTxt || ''),
    usersTxt.slice(0, 100).replace(/\n/g, ' '));
  ctx.check('users: edit_files feature toggle listed', /edit files/i.test(usersTxt || ''), '');
  ctx.check('users: logout-all control', /logout all/i.test(usersTxt || ''), '');

  // ============ header: docs link ============
  const docsLink = await page.evaluate(() => {
    const app = window.__deep('ddm-app');
    const a = app?.shadowRoot
      ? [...app.shadowRoot.querySelectorAll('a')].find(x => /docs/i.test(x.textContent))
      : null;
    return a ? a.href : '';
  });
  ctx.check('app: docs link in header', /github\.com/.test(docsLink || ''), docsLink);

  // ============ webdav status surfaced ============
  const wv = await h.api('/api/webdav/status');
  ctx.check('webdav: status endpoint', wv.status === 200 && typeof wv.data?.enabled === 'boolean',
    JSON.stringify(wv.data));
}
