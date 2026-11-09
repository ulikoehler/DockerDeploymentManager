import { CONFIG, sleep } from '../lib/harness.mjs';

export default async function (h) {
  const { ctx, page } = h;
  const svc = CONFIG.svc;
  await h.goto(`/service/${svc}`);
  await sleep(1000);

  // ---- compose ----
  await h.tab('Compose');
  // save (no-op content) works
  let r = await page.evaluate(async () => {
    const ok = window.__clickText('save');
    await new Promise(r => setTimeout(r, 2000));
    return ok;
  });
  ctx.check('compose: save button', r === true);

  // invalid YAML -> error surfaced in panel
  r = await page.evaluate(async () => {
    const ce = window.__deep('ddm-compose-editor');
    const ta = ce && ce.shadowRoot ? ce.shadowRoot.querySelector('textarea') : null;
    if (!ta) return { err: 'no textarea' };
    window.__setVal(ta, 'this is: [not: valid: yaml');
    await new Promise(r => setTimeout(r, 300));
    window.__clickText('save');
    await new Promise(r => setTimeout(r, 2500));
    return { msg: ce.shadowRoot.textContent.slice(0, 300) };
  });
  ctx.check('compose: invalid yaml shows error', /error|invalid|fail|400/i.test(r.msg || ''), (r.msg || r.err || '').slice(0, 100));

  // restore valid compose via API (UI save of broken yaml must not have persisted)
  const good = await h.api(`/api/services/${svc}/compose`, { method: 'PUT', body: { content: 'services:\n  web:\n    image: nginx:alpine\n' } });
  ctx.check('compose: restore valid via api', good.status === 200, `status=${good.status}`);

  // privileged compose: denied under strict/infra, allowed under unrestricted —
  // assert whichever outcome the effective policy implies, and that the UI explains it
  const effPol = await h.api('/api/policy');
  const polName = effPol.data?.policy || effPol.data?.effective || '';
  const privilegedDenied = effPol.data?.rules?.deny_privileged === true ||
    ['strict', 'infra'].includes(String(polName));
  const afterPriv = await page.evaluate(async () => {
    const ce = window.__deep('ddm-compose-editor');
    if (!ce) return { err: 'no compose editor' };
    const ta = ce.shadowRoot.querySelector('textarea');
    if (!ta) return { err: 'no textarea' };
    window.__setVal(ta, 'services:\n  web:\n    image: nginx:alpine\n    privileged: true\n');
    await new Promise(r => setTimeout(r, 300));
    window.__clickText('save');
    await new Promise(r => setTimeout(r, 2500));
    return { msg: ce.shadowRoot.textContent.slice(0, 400) };
  });
  const compAfter = await h.api(`/api/services/${svc}/compose`);
  const stillPriv = String(compAfter.data?.content || '').includes('privileged: true');
  if (privilegedDenied) {
    ctx.check('compose: privileged denied + error shown', !stillPriv && /privileged|denied|policy|violation|error/i.test(afterPriv.msg || ''), (afterPriv.msg || '').slice(0, 120));
    // policy rejections must explain the remediation, not just the violation
    ctx.check('compose: policy error names remediation', /compose policy|Users/i.test(afterPriv.msg || ''), (afterPriv.msg || '').slice(0, 160));
  } else {
    ctx.check('compose: privileged allowed under ' + polName, stillPriv === true, (afterPriv.msg || '').slice(0, 120));
  }
  // the editor shows which policy is enforced
  const polTxt = await page.evaluate(() => {
    const ce = window.__deep('ddm-compose-editor');
    return ce?.shadowRoot?.textContent || '';
  });
  ctx.check('compose: enforced policy displayed', new RegExp('enforced compose policy: ' + polName, 'i').test(polTxt), polTxt.slice(0, 80));
  await h.api(`/api/services/${svc}/compose`, { method: 'PUT', body: { content: 'services:\n  web:\n    image: nginx:alpine\n' } });

  // ---- files ----
  await h.tab('Files');
  // go to root via breadcrumb
  await page.evaluate((n) => { const a = window.__deepAll('a').find(e => e.textContent.trim() === n); if (a) a.click(); }, svc);
  await sleep(700);

  // new file -> auto-browses into it -> type -> save
  r = await page.evaluate(async () => {
    const inp = window.__deep('input[placeholder="name"]');
    if (!inp) return { err: 'no name input' };
    window.__setVal(inp, 'e2e_ui.txt');
    await new Promise(r => setTimeout(r, 300));
    window.__clickText('new file');
    await new Promise(r => setTimeout(r, 1200));
    const ta = window.__deep('textarea');
    if (!ta) return { err: 'no textarea after new file' };
    window.__setVal(ta, 'ui-e2e-content\n');
    await new Promise(r => setTimeout(r, 300));
    const saveBtn = window.__deepAll('button').find(b => b.textContent.trim() === 'save' && !b.disabled && b.offsetParent);
    if (!saveBtn) return { err: 'save disabled' };
    saveBtn.click();
    await new Promise(r => setTimeout(r, 1200));
    return { ok: true };
  });
  let f = await h.api(`/api/services/${svc}/files?path=e2e_ui.txt`);
  ctx.check('files: new file + edit + save', r.ok === true && f.status === 200 && String(f.data?.content || '').includes('ui-e2e-content'), `api=${f.status}`);

  // back to root, mkdir
  await page.evaluate((n) => { const a = window.__deepAll('a').find(e => e.textContent.trim() === n); if (a) a.click(); }, svc);
  await sleep(700);
  r = await page.evaluate(async () => {
    const inp = window.__deep('input[placeholder="name"]');
    if (!inp) return { err: 'no input' };
    window.__setVal(inp, 'e2e_dir');
    await new Promise(r => setTimeout(r, 300));
    window.__clickText('mkdir');
    await new Promise(r => setTimeout(r, 1200));
    return { ok: true };
  });
  f = await h.api(`/api/services/${svc}/files?path=e2e_dir`);
  ctx.check('files: mkdir', r.ok === true && f.status === 200 && f.data?.kind === 'Dir', `kind=${f.data?.kind}`);

  // rename e2e_ui.txt -> e2e_renamed.txt (prompt dialog)
  h.ctx.expectDialog('e2e_renamed.txt');
  r = await page.evaluate(async () => {
    const ff = window.__deep('ddm-files');
    const rows = [...ff.shadowRoot.querySelectorAll('tr')];
    const row = rows.find(x => x.textContent.includes('e2e_ui.txt'));
    const btn = row && [...row.querySelectorAll('button')].find(b => b.textContent.trim() === 'rename');
    if (!btn) return { err: 'no rename btn' };
    btn.click();
    await new Promise(r => setTimeout(r, 1500));
    return { ok: true };
  });
  await sleep(600);
  const fNew = await h.api(`/api/services/${svc}/files?path=e2e_renamed.txt`);
  const fOld = await h.api(`/api/services/${svc}/files?path=e2e_ui.txt`);
  ctx.check('files: rename via prompt', r.ok === true && fNew.status === 200 && fOld.status !== 200, `new=${fNew.status} old=${fOld.status}`);

  // delete e2e_renamed.txt (confirm dialog)
  h.ctx.expectDialog();
  r = await page.evaluate(async () => {
    const ff = window.__deep('ddm-files');
    const rows = [...ff.shadowRoot.querySelectorAll('tr')];
    const row = rows.find(x => x.textContent.includes('e2e_renamed.txt'));
    const btn = row && [...row.querySelectorAll('button')].find(b => b.textContent.trim() === 'delete');
    if (!btn) return { err: 'no delete btn' };
    btn.click();
    await new Promise(r => setTimeout(r, 1500));
    return { ok: true };
  });
  await sleep(600);
  const fDel = await h.api(`/api/services/${svc}/files?path=e2e_renamed.txt`);
  ctx.check('files: delete via confirm', r.ok === true && fDel.status !== 200, `status=${fDel.status}`);

  // regression: clicking a file must load its content into the editor —
  // the API node kind is "File" (serde variant), not "file"
  const w = await h.api(`/api/services/${svc}/files`, { method: 'PUT', body: { path: 'e2e_ui.txt', content: 'ui-content-marker' } });
  ctx.check('files: seed content file', w.status === 200, `status=${w.status}`);
  r = await page.evaluate(async () => {
    const ff = window.__deep('ddm-files');
    // back to root via the first breadcrumb segment (service name)
    const seg = [...ff.shadowRoot.querySelectorAll('a')][0];
    if (seg) seg.click();
    await new Promise(r => setTimeout(r, 800));
    const link = [...ff.shadowRoot.querySelectorAll('a')].find(a => a.textContent.includes('e2e_ui.txt'));
    if (!link) return { err: 'no file link' };
    link.click();
    await new Promise(r => setTimeout(r, 1200));
    const ta = ff.shadowRoot.querySelector('textarea');
    return { ok: !!ta && ta.value.includes('ui-content-marker'), val: ta ? ta.value.slice(0, 60) : '' };
  });
  ctx.check('files: file content loads in editor', r.ok === true, (r.val || r.err || '').slice(0, 80));

  // cleanup dir via API
  await h.api(`/api/services/${svc}/files?path=e2e_dir`, { method: 'DELETE' });
  await h.api(`/api/services/${svc}/files?path=e2e_ui.txt`, { method: 'DELETE' });
}
