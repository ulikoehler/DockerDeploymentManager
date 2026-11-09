import { CONFIG, sleep } from '../lib/harness.mjs';

export default async function (h) {
  const { ctx, page } = h;
  const { url, user, pass } = CONFIG;

  // bad login shows an error and does not authenticate.
  // run.mjs already logged in — clear the session to see the login form.
  await page.evaluate(() => { sessionStorage.clear(); localStorage.clear(); });
  await page.goto(`${url}/`, { waitUntil: 'networkidle0' });
  await page.waitForSelector('ddm-app >>> input[name=name]', { timeout: 40000 });
  await page.type('ddm-app >>> input[name=name]', user);
  await page.type('ddm-app >>> input[name=password]', 'definitely-wrong-password');
  await page.click('ddm-app >>> button');
  await sleep(2000);
  // error renders inside ddm-login's shadow root — pierce it
  const errTxt = await page.evaluate(() => {
    const deep = (sel, root = document) => {
      const h = root.querySelector(sel); if (h) return h;
      for (const e of root.querySelectorAll('*')) { if (e.shadowRoot) { const x = deep(sel, e.shadowRoot); if (x) return x; } }
      return null;
    };
    const login = deep('ddm-login');
    const errEl = deep('.error, .err, [class*=error]');
    return ((login && login.shadowRoot ? login.shadowRoot.textContent : '') + ' ' + (errEl ? errEl.textContent : '') + ' ' + document.body.innerText).toLowerCase();
  });
  ctx.check('auth: invalid login shows error', /invalid|incorrect|failed|credentials|error/i.test(errTxt), errTxt.slice(0, 80));
  const noToken = await page.evaluate(() => !sessionStorage.getItem('ddm_token'));
  ctx.check('auth: invalid login does not store token', noToken);

  // good login
  await h.login();
  const me = await h.api('/api/auth/me');
  ctx.check('auth: login + /api/auth/me', me.status === 200 && me.data?.name === user, `user=${me.data?.name}`);

  // unauthorized API without token
  const unauth = await page.evaluate(async (u) => {
    const r = await fetch(`${u}/api/services`);
    return r.status;
  }, url);
  ctx.check('auth: unauthenticated API rejected', unauth === 401, `status=${unauth}`);
}
