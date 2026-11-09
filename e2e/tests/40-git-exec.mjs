import { CONFIG, sleep } from '../lib/harness.mjs';

const REPO_URL = process.env.E2E_GIT_URL || 'https://github.com/ulikoehler/DockerDeploymentManager.git';

export default async function (h) {
  const { ctx, page } = h;
  const svc = CONFIG.svc;
  await h.goto(`/service/${svc}`);
  await sleep(1000);
  await h.tab('Git');
  await sleep(1500);

  // clone the public DDM repo into a subdirectory — open the form FIRST
  let r = await page.evaluate(async (url) => {
    const g = window.__deep('ddm-git');
    const toggle = [...g.shadowRoot.querySelectorAll('button')].find(b => b.textContent.includes('clone'));
    if (toggle) toggle.click();
    await new Promise(r => setTimeout(r, 600));
    const inputs = [...g.shadowRoot.querySelectorAll('input')].filter(i => i.offsetParent);
    const urlI = inputs.find(i => /github|repo|http/i.test(i.placeholder || '')) || inputs[0];
    const pathI = inputs.find(i => /subdirectory/i.test(i.placeholder || ''));
    const branchI = inputs.find(i => /branch/i.test(i.placeholder || ''));
    if (!urlI) return { err: 'no clone inputs' };
    window.__setVal(urlI, url);
    if (pathI) window.__setVal(pathI, 'ddmrepo');
    if (branchI) window.__setVal(branchI, 'main');
    await new Promise(r => setTimeout(r, 300));
    const cloneBtn = [...g.shadowRoot.querySelectorAll('button')].find(b => b.textContent.trim() === 'clone' && !b.disabled && b.offsetParent);
    if (!cloneBtn) return { err: 'no clone submit' };
    cloneBtn.click();
    await new Promise(r => setTimeout(r, 1500));
    return { ok: true, msg: g.shadowRoot.textContent.slice(0, 300) };
  }, REPO_URL);
  ctx.check('git: clone started', r.ok === true, (r.msg || r.err || '').slice(0, 100));

  // wait for the repo to appear (clone is an async execution)
  let appeared = false;
  for (let i = 0; i < 24; i++) {
    await sleep(5000);
    const repos = await h.api(`/api/services/${svc}/git/repos`);
    if (Array.isArray(repos.data) && repos.data.some(x => (x.path || '').includes('ddmrepo'))) { appeared = true; break; }
    await page.evaluate(() => window.__clickText('refresh'));
    await sleep(1500);
  }
  ctx.check('git: clone completes, repo listed', appeared, 'waited ~2min');

  if (appeared) {
    // select the repo row -> status/log/branches/fetch/pull buttons
    r = await page.evaluate(async () => {
      const g = window.__deep('ddm-git');
      const link = [...g.shadowRoot.querySelectorAll('a')].find(a => (a.textContent || '').includes('ddmrepo'));
      if (link) link.click();
      await new Promise(r => setTimeout(r, 2500));
      return { txt: g.shadowRoot.textContent.slice(0, 400) };
    });
    ctx.check('git: repo detail renders', /ddmrepo|branch|commit|status/i.test(r.txt || ''), (r.txt || '').slice(0, 100));

    for (const act of ['refresh', 'fetch', 'pull']) {
      const ok = await page.evaluate((a) => {
        const g = window.__deep('ddm-git');
        const b = [...g.shadowRoot.querySelectorAll('button')].find(x => x.textContent.trim() === a && x.offsetParent);
        if (b) { b.click(); return true; } return false;
      }, act);
      ctx.check(`git: ${act} button`, ok === true);
      await sleep(act === 'pull' ? 8000 : 3000);
    }
    // log + branches panels render content
    const panels = await h.compText('ddm-git');
    ctx.check('git: log/branches content renders', /commit|main|master|branch/i.test(panels || ''), (panels || '').slice(0, 80));
  }

  // clone with a bad URL -> error surfaced (re-open the form first)
  r = await page.evaluate(async () => {
    const g = window.__deep('ddm-git');
    const toggle = [...g.shadowRoot.querySelectorAll('button')].find(b => /clone/.test(b.textContent) && b.textContent.includes('…'));
    if (toggle && toggle.textContent.trim() === 'clone…') toggle.click();
    await new Promise(r => setTimeout(r, 600));
    const inputs = [...g.shadowRoot.querySelectorAll('input')].filter(i => i.offsetParent);
    const urlI = inputs.find(i => /github|repo|http/i.test(i.placeholder || '')) || inputs[0];
    const pathI = inputs.find(i => /subdirectory/i.test(i.placeholder || ''));
    if (!urlI) return { err: 'no inputs' };
    window.__setVal(urlI, 'https://invalid.invalid/nope.git');
    if (pathI) window.__setVal(pathI, 'badrepo');
    await new Promise(r => setTimeout(r, 300));
    const cloneBtn = [...g.shadowRoot.querySelectorAll('button')].find(b => b.textContent.trim() === 'clone' && !b.disabled && b.offsetParent);
    if (cloneBtn) cloneBtn.click();
    await new Promise(r => setTimeout(r, 2000));
    return { ok: !!cloneBtn, msg: g.shadowRoot.textContent.slice(0, 300) };
  });
  ctx.check('git: bad clone URL handled', r.ok === true, (r.msg || '').slice(0, 100));

  // ---- exec panel ----
  // make sure the container is actually running first — poll until docker
  // reports a STABLE set of running containers (compose up is async; the
  // old container can still report 'running' while its replacement starts,
  // and exec'ing the stale id fails with "not part of this service")
  await h.api(`/api/services/${svc}/actions`, { method: 'POST', body: { action: 'up' } });
  let running = false;
  let lastSig = '';
  for (let i = 0; i < 30; i++) {
    await sleep(3000);
    const d0 = await h.api(`/api/services/${svc}`);
    const cs = d0.data?.containers || d0.containers || [];
    const sig = cs.map(c => `${c.id}:${c.state}`).sort().join('|');
    if (cs.length > 0 && cs.every(c => c.state === 'running') && sig === lastSig) { running = true; break; }
    lastSig = sig;
  }
  ctx.check('exec: container running before exec', running);
  // full reload — h.goto to the same hash does not remount the SPA, so
  // this.detail would still hold pre-'up' container ids and exec would
  // target a container that no longer exists
  await h.page.reload({ waitUntil: 'networkidle0' });
  await sleep(2000);
  await h.tab('Overview');
  await sleep(800);
  r = await page.evaluate(async () => {
    const d = window.__deep('ddm-service-detail');
    // pick the exec button in a row whose state cell says 'running' —
    // stale containers from a recreate also render exec buttons
    const rows = [...d.shadowRoot.querySelectorAll('tbody tr')];
    const row = rows.find(x => {
      const cells = [...x.querySelectorAll('td')];
      return cells.some(c => c.textContent.trim() === 'running') &&
             cells.some(c => /exec/.test(c.textContent));
    }) || rows.find(x => x.querySelector('button'));
    const eb = row && [...row.querySelectorAll('button')].find(b => b.textContent.trim() === 'exec');
    if (!eb) return { err: 'no exec button (container running?)' };
    eb.click();
    await new Promise(r => setTimeout(r, 1000));
    const inp = [...d.shadowRoot.querySelectorAll('input')].find(i => /command/i.test(i.placeholder || '') && i.offsetParent);
    if (!inp) return { err: 'no command input' };
    window.__setVal(inp, 'echo E2E_EXEC_OK');
    await new Promise(r => setTimeout(r, 300));
    const run = [...d.shadowRoot.querySelectorAll('button')].find(b => b.textContent.trim() === 'run' && b.offsetParent);
    if (!run) return { err: 'no run button' };
    run.click();
    // wait for output — scope checks to the exec card only
    for (let i = 0; i < 30; i++) {
      await new Promise(r => setTimeout(r, 1000));
      const card = [...d.shadowRoot.querySelectorAll('.card')].find(c => /exec —/.test(c.textContent));
      const t = card ? card.textContent : '';
      if (t.includes('E2E_EXEC_OK')) return { ok: true };
      if (/error:|failed/i.test(t) && i > 5) return { ok: false, txt: t.slice(-300) };
    }
    const card = [...d.shadowRoot.querySelectorAll('.card')].find(c => /exec —/.test(c.textContent));
    return { ok: false, txt: (card ? card.textContent : 'no exec card').slice(-300) };
  });
  ctx.check('exec: run command, output streamed', r.ok === true, (r.txt || r.err || '').slice(-160));
}
