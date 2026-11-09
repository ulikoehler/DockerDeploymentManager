import { CONFIG, sleep, ensureService, deleteService } from '../lib/harness.mjs';

export default async function (h) {
  const { ctx } = h;
  const svc = CONFIG.svc;

  await ensureService(h);
  ctx.pass('lifecycle: scratch service up', svc);

  // service list shows it with action buttons — poll: the SPA may already
  // be mounted on the list view and not refetch after API-side creation
  let rowInfo = {};
  for (let i = 0; i < 10; i++) {
    rowInfo = await page_row_buttons(h, svc);
    if (rowInfo.hasRestart) break;
    await h.page.reload({ waitUntil: 'networkidle0' }).catch(() => {});
    await sleep(2000);
  }
  ctx.check('lifecycle: list row has action buttons', rowInfo.hasRestart && rowInfo.hasDown, JSON.stringify(rowInfo));

  // detail page: all tabs render
  await h.goto(`/service/${svc}`);
  await sleep(1200);
  const tabs = ['Overview', 'Logs', 'Compose', 'Files', 'Git', 'Unit', 'Backup', 'Monitoring'];
  let allTabs = true;
  for (const t of tabs) {
    const ok = await h.clickText(t);
    if (!ok) { allTabs = false; ctx.fail(`lifecycle: tab ${t} clickable`); }
    await sleep(700);
  }
  ctx.check('lifecycle: all 8 tabs clickable', allTabs);

  // toolbar actions: restart (real), up (already up -> graceful), update, pull, enable, disable
  for (const a of ['restart', 'up', 'update', 'pull', 'enable', 'disable']) {
    const clicked = await h.page.evaluate((act) => {
      const d = window.__deep('ddm-service-detail');
      const b = [...d.shadowRoot.querySelectorAll('.toolbar button')].find(x => x.textContent.trim() === act);
      if (b) { b.click(); return true; } return false;
    }, a);
    ctx.check(`lifecycle: toolbar ${a} clickable`, clicked === true);
    await sleep(2500);
  }
  // service still exists and is reachable after the action storm
  const after = await h.api(`/api/services/${svc}`);
  ctx.check('lifecycle: service survives action storm', after.status === 200, `status=${after.status}`);

  // create a second service via the UI form, then delete it via UI
  const tmp = 'e2e-tmp-svc';
  await h.api(`/api/services/${tmp}`, { method: 'DELETE', body: { force: true } }).catch(() => {});
  await h.goto('/create');
  await sleep(800);
  const created = await h.page.evaluate(async () => {
    const nameI = window.__deepAll('input').find(i => i.offsetParent && /service/i.test(i.placeholder || ''));
    const ta = window.__deep('textarea');
    if (!nameI || !ta) return { err: 'inputs missing' };
    window.__setVal(nameI, 'e2e-tmp-svc');
    window.__setVal(ta, 'services:\n  web:\n    image: nginx:alpine\n');
    await new Promise(r => setTimeout(r, 300));
    const ok = window.__clickText('create');
    await new Promise(r => setTimeout(r, 2500));
    return { clicked: ok };
  });
  const chk = await h.api(`/api/services/${tmp}`);
  ctx.check('lifecycle: create form makes service', created.clicked === true && chk.status === 200, `api=${chk.status}`);
  if (chk.status === 200) {
    await h.api(`/api/services/${tmp}`, { method: 'DELETE', body: { force: true } });
    ctx.pass('lifecycle: api cleanup of temp service');
  }
}

async function page_row_buttons(h, name) {
  return h.page.evaluate((n) => {
    const sl = window.__deep('ddm-service-list');
    if (!sl || !sl.shadowRoot) return {};
    const rows = [...sl.shadowRoot.querySelectorAll('tr')];
    const row = rows.find(r => r.textContent.includes(n));
    if (!row) return {};
    const btns = [...row.querySelectorAll('button')].map(b => b.textContent.trim());
    return { hasRestart: btns.includes('restart'), hasDown: btns.includes('down'), btns };
  }, name);
}
