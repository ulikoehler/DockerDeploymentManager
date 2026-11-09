import { CONFIG, sleep } from '../lib/harness.mjs';

export default async function (h) {
  const { ctx, page } = h;

  // ============ commands view ============
  await h.goto('/commands');
  await sleep(1500);
  const cmdTxt = await h.compText('ddm-commands');
  ctx.check('commands: view renders', cmdTxt.length > 10, cmdTxt.slice(0, 80).replace(/\n/g, ' '));
  // if sections exist, run the first item and watch for output
  const hasRun = await page.evaluate(() => {
    const c = window.__deep('ddm-commands');
    const b = [...c.shadowRoot.querySelectorAll('button')].find(x => /run/i.test(x.textContent) && x.offsetParent);
    if (b) { b.click(); return true; } return false;
  });
  if (hasRun) {
    await sleep(6000);
    const out = await h.compText('ddm-commands');
    ctx.check('commands: run produces output/finish', /finished|success|output|error/i.test(out || ''), out.slice(0, 100).replace(/\n/g, ' '));
  } else {
    ctx.pass('commands: no runnable sections configured (skipped run)');
  }

  // ============ events view ============
  await h.goto('/events');
  await sleep(1500);
  const evTxt = await h.compText('ddm-events-view');
  ctx.check('events: view renders', evTxt.length > 5, evTxt.slice(0, 80).replace(/\n/g, ' '));

  // ============ gitops view ============
  await h.goto('/gitops');
  await sleep(1500);
  const goTxt = await h.compText('ddm-gitops-panel');
  const goOk = /disabled|repository|sync|enabled/i.test(goTxt || '');
  ctx.check('gitops: view renders state', goOk, goTxt.slice(0, 100).replace(/\n/g, ' '));

  // ============ mobile smoke ============
  await page.setViewport({ width: 390, height: 844 });
  await page.goto(`${process.env.DDM_URL || 'http://localhost:8080'}/#/`, { waitUntil: 'networkidle0' });
  await sleep(3000);
  const mob = await page.evaluate(() => {
    const sl = window.__deep('ddm-service-list');
    // innerText doesn't pierce shadow DOM — count rendered rows instead
    const rows = sl && sl.shadowRoot ? sl.shadowRoot.querySelectorAll('tbody tr').length : 0;
    return { list: !!sl, rows };
  });
  ctx.check('mobile: service list renders at 390px', mob.list === true && mob.rows > 0, `rows=${mob.rows}`);
  await page.setViewport({ width: 1920, height: 1080 });
}
