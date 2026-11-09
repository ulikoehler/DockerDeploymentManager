// Batch-4 coverage: CodeMirror editors, API reference view, image preview hook.
import { ensureService, sleep } from '../lib/harness.mjs';

export default async function (h) {
  const ctx = h.ctx;
  const { page } = h;
  await ensureService(h);

  // --- API reference view --------------------------------------------------
  await h.goto('/api');
  await sleep(1000);
  const apiTxt = await h.compText('ddm-api-docs');
  ctx.check('api: reference view renders', /API reference/.test(apiTxt) && /\/api\/services/.test(apiTxt), apiTxt.slice(0, 60));
  ctx.check('api: documents auth + ws', /Bearer/.test(apiTxt) && /\/ws\//.test(apiTxt));

  // --- CodeMirror in compose editor ----------------------------------------
  await h.goto('/service/e2e-svc');
  await h.tab('Compose');
  await sleep(1200);
  const cm = await page.evaluate(() => {
    const d = window.__deep('ddm-compose-editor');
    return !!d?.shadowRoot?.querySelector('ddm-code-editor');
  });
  ctx.check('compose: CodeMirror editor mounted', cm);
  const cmInner = await page.evaluate(() => {
    const d = window.__deep('ddm-compose-editor');
    const ed = d?.shadowRoot?.querySelector('ddm-code-editor');
    return !!ed?.shadowRoot?.querySelector('.cm-editor');
  });
  ctx.check('compose: cm-editor DOM present', cmInner);

  // --- CodeMirror in files editor ------------------------------------------
  await h.tab('Files');
  await sleep(1200);
  // open docker-compose.yml
  await page.evaluate(() => {
    const f = window.__deep('ddm-files');
    const links = [...f.shadowRoot.querySelectorAll('a')];
    const l = links.find(a => /docker-compose/.test(a.textContent));
    if (l) l.click();
  });
  await sleep(1200);
  const fileCm = await page.evaluate(() => {
    const f = window.__deep('ddm-files');
    const ed = f?.shadowRoot?.querySelector('ddm-code-editor');
    return !!ed?.shadowRoot?.querySelector('.cm-editor');
  });
  ctx.check('files: CodeMirror editor for file', fileCm);

  // --- CodeMirror in unit editor -------------------------------------------
  await h.tab('Unit');
  await sleep(1000);
  const unitCm = await page.evaluate(() => {
    const d = window.__deep('ddm-unit-editor');
    return !!d?.shadowRoot?.querySelector('ddm-code-editor .cm-editor, ddm-code-editor');
  });
  ctx.check('unit: CodeMirror editor mounted', unitCm);

  // --- CodeMirror in backup stdin_dumps --------------------------------------
  await h.tab('Backup');
  await sleep(1000);
  const bkBtn = await page.evaluate(() => window.__clickIn('ddm-backup-panel', 'config'));
  if (bkBtn) {
    await sleep(800);
    const adv = await page.evaluate(() => {
      const c = window.__deep('ddm-backup-panel');
      const det = [...c.shadowRoot.querySelectorAll('details')].find(d => /advanced/.test(d.textContent));
      if (det) det.open = true;
      return !!det;
    });
    if (adv) {
      await sleep(600);
      const dumpsCm = await page.evaluate(() => {
        const c = window.__deep('ddm-backup-panel');
        return [...c.shadowRoot.querySelectorAll('ddm-code-editor')].length;
      });
      ctx.check('backup: stdin_dumps uses code editor', dumpsCm >= 1, `editors=${dumpsCm}`);
    } else ctx.check('backup: stdin_dumps uses code editor', false, 'no advanced section');
    // cancel editing
    await page.evaluate(() => window.__clickIn('ddm-backup-panel', 'cancel'));
  } else ctx.check('backup: config button', false);
}
