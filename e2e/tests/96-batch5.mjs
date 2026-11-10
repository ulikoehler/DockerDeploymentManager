// Batch-5 coverage: session management, styled dialogs, theme toggle,
// service favorites, git diff endpoint.
import { CONFIG, ensureService, sleep } from '../lib/harness.mjs';

export default async function (h) {
  const ctx = h.ctx;
  const { page } = h;
  await ensureService(h);

  // --- sessions are registered and listed -------------------------------
  const toks = await h.api('/api/auth/tokens');
  const sessions = (toks.data ?? []).filter((t) => t.kind === 'session' && !t.revoked);
  ctx.check('sessions: login session registered', sessions.length >= 1, `sessions=${sessions.length}`);

  await h.goto('/token');
  await sleep(1200);
  const tokTxt = await h.compText('ddm-token');
  ctx.check('tokens: sessions & tokens table', /sessions & tokens/.test(tokTxt) && /session/.test(tokTxt));

  // --- revoking a second session kills it immediately -------------------
  const login = await page.evaluate(async (u, p) => {
    const r = await fetch('/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: u, password: p }),
    });
    return r.json();
  }, CONFIG.user, CONFIG.pass);
  const tok2 = login?.data?.token;
  ctx.check('sessions: second login issued', !!tok2);
  if (tok2) {
    const jti2 = JSON.parse(atob(tok2.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).jti;
    const me2before = await page.evaluate(async (t) => {
      const r = await fetch('/api/auth/me', { headers: { Authorization: `Bearer ${t}` } });
      return r.status;
    }, tok2);
    const rev = await h.api(`/api/auth/tokens/${jti2}`, { method: 'DELETE' });
    const me2after = await page.evaluate(async (t) => {
      const r = await fetch('/api/auth/me', { headers: { Authorization: `Bearer ${t}` } });
      return r.status;
    }, tok2);
    ctx.check('sessions: revoke endpoint ok', rev.status === 200, `status=${rev.status}`);
    ctx.check('sessions: revoked session rejected', me2before === 200 && me2after === 401,
      `before=${me2before} after=${me2after}`);
  }

  // --- git diff endpoint wired ------------------------------------------
  const diff = await h.api('/api/services/e2e-svc/git/diff');
  ctx.check('git: diff endpoint responds', diff.status === 400 || diff.status === 200,
    `status=${diff.status} ${JSON.stringify(diff.data).slice(0, 60)}`);

  // --- styled dialogs replace native prompt/confirm ----------------------
  // files: create a scratch file, hit delete, expect our modal (not a page dialog)
  const w = await h.api('/api/services/e2e-svc/files', {
    method: 'PUT',
    body: { path: 'ddm-dialog-test.txt', content: 'x' },
  });
  ctx.check('dialogs: test file written', w.status === 200, `status=${w.status}`);
  await h.goto('/service/e2e-svc');
  await h.tab('Files');
  await sleep(1500);
  // browse root already; click delete on our file if listed
  const clicked = await page.evaluate(() => {
    const f = window.__deep('ddm-files');
    const tr = [...f.shadowRoot.querySelectorAll('tr')]
      .find(r => /ddm-dialog-test\.txt/.test(r.textContent));
    const btn = tr?.querySelector('button.danger');
    if (btn) { btn.click(); return true; }
    return false;
  });
  if (clicked) {
    await sleep(500);
    const dlg = await page.evaluate(() => !!document.querySelector('#ddm-dialog-root .modal'));
    ctx.check('dialogs: styled confirm opens (no native dialog)', dlg);
    // cancel it
    await page.evaluate(() => {
      const b = [...document.querySelectorAll('#ddm-dialog-root button')].find(x => /cancel/i.test(x.textContent));
      b?.click();
    });
    await sleep(300);
    const stillThere = await page.evaluate(() => {
      const f = window.__deep('ddm-files');
      return /ddm-dialog-test\.txt/.test(f.shadowRoot.textContent);
    });
    ctx.check('dialogs: cancel keeps file', stillThere);
    await h.api('/api/services/e2e-svc/files?path=ddm-dialog-test.txt', { method: 'DELETE' }).catch(() => {});
  } else {
    ctx.check('dialogs: styled confirm opens', false, 'delete button not found for test file');
    await h.api('/api/services/e2e-svc/files?path=ddm-dialog-test.txt', { method: 'DELETE' }).catch(() => {});
  }

  // --- theme toggle --------------------------------------------------------
  const before = await page.evaluate(() => document.documentElement.dataset.theme || 'dark');
  await page.evaluate(() => window.__clickText('☀') || window.__clickText('☾'));
  await sleep(400);
  const after = await page.evaluate(() => document.documentElement.dataset.theme || 'dark');
  ctx.check('theme: toggle switches data-theme', before !== after, `${before}→${after}`);
  const persisted = await page.evaluate(() => localStorage.getItem('ddm:theme'));
  ctx.check('theme: persisted to localStorage', persisted === after, `stored=${persisted}`);
  // toggle back to original
  await page.evaluate(() => window.__clickText('☀') || window.__clickText('☾'));
  await sleep(300);

  // --- service favorites ---------------------------------------------------
  await h.goto('/');
  await sleep(1500);
  const favBtn = await page.evaluate(() => {
    const l = window.__deep('ddm-service-list');
    const btns = [...l.shadowRoot.querySelectorAll('button')].filter(b => /☆|★/.test(b.textContent));
    const target = btns.find(b => {
      const td = b.closest('td');
      return /e2e-svc/.test(td?.textContent ?? '');
    }) ?? btns[0];
    if (target) { target.click(); return target.textContent.trim(); }
    return null;
  });
  ctx.check('favorites: star button present', !!favBtn, `clicked=${favBtn}`);
  if (favBtn) {
    await sleep(400);
    const favs = await page.evaluate(() => JSON.parse(localStorage.getItem('ddm:favs') ?? '[]'));
    ctx.check('favorites: persisted', favs.includes('e2e-svc'), JSON.stringify(favs));
    const starNow = await page.evaluate(() => {
      const l = window.__deep('ddm-service-list');
      return [...l.shadowRoot.querySelectorAll('button')].some(b => b.textContent.trim() === '★');
    });
    ctx.check('favorites: star renders filled', starNow);
    // unstar to leave clean state
    await page.evaluate(() => {
      const l = window.__deep('ddm-service-list');
      const b = [...l.shadowRoot.querySelectorAll('button')].find(x => x.textContent.trim() === '★' &&
        /e2e-svc/.test(x.closest('td')?.textContent ?? ''));
      b?.click();
    });
    await sleep(300);
  }

  // --- monitoring recent events section ------------------------------------
  await h.goto('/service/e2e-svc');
  await h.tab('Monitoring');
  await sleep(1500);
  const monTxt = await h.compText('ddm-service-monitoring');
  ctx.check('monitoring: recent events heading present', /Recent events|no active checks/.test(monTxt));
}
