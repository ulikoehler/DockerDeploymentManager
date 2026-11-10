// E2E harness: browser launch, login, shadow-DOM helpers, API access, dialogs.
// Env: DDM_URL (default http://localhost:8080), DDM_USER, DDM_PASS,
//      CHROME (default google-chrome), E2E_SVC (default e2e-svc).
import puppeteer from 'puppeteer-core';

export const CONFIG = {
  url: process.env.DDM_URL || 'http://localhost:8080',
  user: process.env.DDM_USER || 'admin',
  pass: process.env.DDM_PASS || '',
  chrome: process.env.CHROME || 'google-chrome',
  svc: process.env.E2E_SVC || 'e2e-svc',
};

export class Ctx {
  constructor() {
    this.results = [];
    this.dialogQueue = [];
  }
  pass(name, detail = '') { this.results.push({ name, ok: true, detail }); console.log('  PASS', name, detail); }
  fail(name, detail = '') { this.results.push({ name, ok: false, detail }); console.log('  FAIL', name, detail); }
  check(name, ok, detail = '') { ok ? this.pass(name, detail) : this.fail(name, detail); }
  // Queue a response for the next window.confirm()/prompt().
  // value === undefined -> plain accept (confirm); string -> prompt answer.
  expectDialog(value) { this.dialogQueue.push(value); }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export { sleep };

export async function launch() {
  const ctx = new Ctx();
  const browser = await puppeteer.launch({
    executablePath: process.env.CHROME_PATH || '/usr/bin/google-chrome',
    headless: 'new',
    args: ['--no-sandbox'],
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1920, height: 1080 });

  page.on('dialog', async (d) => {
    const v = ctx.dialogQueue.shift();
    if (d.type() === 'prompt') await d.accept(v === undefined ? '' : v);
    else if (v === false) await d.dismiss();
    else await d.accept();
  });
  page.on('pageerror', (e) => console.log('  [pageerror]', String(e).slice(0, 200)));

  // Shadow-piercing helpers, available in every evaluate.
  await page.evaluateOnNewDocument(`
    window.__deep = (sel, root = document) => {
      const h = root.querySelector(sel); if (h) return h;
      for (const e of root.querySelectorAll('*')) {
        if (e.shadowRoot) { const x = window.__deep(sel, e.shadowRoot); if (x) return x; }
      } return null;
    };
    window.__deepAll = (sel, root = document, out = []) => {
      for (const e of root.querySelectorAll(sel)) out.push(e);
      for (const e of root.querySelectorAll('*')) {
        if (e.shadowRoot) window.__deepAll(sel, e.shadowRoot, out);
      } return out;
    };
    window.__clickText = (txt) => {
      const b = window.__deepAll('button').find(e =>
        e.textContent.trim().toLowerCase().includes(String(txt).toLowerCase()) &&
        e.offsetParent !== null && !e.disabled);
      if (b) { b.click(); return true; } return false;
    };
    window.__setVal = (el, v) => {
      el.value = v;
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    };
    // Find a button inside a specific component's shadow root by exact-ish text.
    window.__clickIn = (compSel, txt) => {
      const c = window.__deep(compSel);
      if (!c || !c.shadowRoot) return false;
      const b = [...c.shadowRoot.querySelectorAll('button')].find(e =>
        e.textContent.trim().toLowerCase().includes(String(txt).toLowerCase()) &&
        e.offsetParent !== null && !e.disabled);
      if (b) { b.click(); return true; } return false;
    };
    window.__compText = (compSel) => {
      const c = window.__deep(compSel);
      return c && c.shadowRoot ? c.shadowRoot.textContent : '';
    };
  `);

  const h = {
    ctx, browser, page,
    sleep,
    async goto(hash) {
      await page.goto(`${CONFIG.url}/#${hash}`, { waitUntil: 'networkidle0' });
      await sleep(1600);
    },
    async clickText(txt) { return page.evaluate((t) => window.__clickText(t), txt); },
    async clickIn(comp, txt) { return page.evaluate((c, t) => window.__clickIn(c, t), comp, txt); },
    async compText(comp) { return page.evaluate((c) => window.__compText(c), comp); },
    /** Answer the app's styled dialog (ddm-dialog-root). Pass a string to
     *  fill the prompt input; omit for a plain confirm. */
    async answerDialog(value) {
      return page.evaluate((v) => {
        const root = document.getElementById('ddm-dialog-root');
        if (!root) return 'no-dialog';
        const input = root.querySelector('input');
        if (input && v !== undefined && v !== null) input.value = v;
        const ok = [...root.querySelectorAll('button')].find(b => !/cancel/i.test(b.textContent));
        if (!ok) return 'no-ok';
        ok.click();
        return 'answered';
      }, value);
    },
    async api(path, opts = {}) {
      return page.evaluate(async (p, o) => {
        const tok = sessionStorage.getItem('ddm_token');
        const r = await fetch(p, {
          headers: { Authorization: `Bearer ${tok}`, ...(o.body ? { 'Content-Type': 'application/json' } : {}) },
          method: o.method || 'GET',
          body: o.body ? JSON.stringify(o.body) : undefined,
        });
        const t = await r.text();
        let j; try { j = JSON.parse(t); } catch { j = { raw: t.slice(0, 120) }; }
        return { status: r.status, data: j.data ?? j };
      }, path, opts);
    },
    async tab(name) {
      await page.evaluate((t) => {
        const d = window.__deep('ddm-service-detail');
        if (d && d.shadowRoot) {
          const b = [...d.shadowRoot.querySelectorAll('.tabs button, button')]
            .find(x => x.textContent.trim() === t && x.offsetParent !== null);
          if (b) b.click();
        }
      }, name);
      await sleep(1300);
    },
    async login(user = CONFIG.user, pass = CONFIG.pass) {
      await page.goto(`${CONFIG.url}/`, { waitUntil: 'networkidle0' });
      await page.waitForSelector('ddm-app >>> input[name=name]', { timeout: 40000 });
      await page.type('ddm-app >>> input[name=name]', user);
      await page.type('ddm-app >>> input[name=password]', pass);
      await page.click('ddm-app >>> button');
      await page.waitForFunction(() => sessionStorage.getItem('ddm_token'), { timeout: 20000 });
      await sleep(1400);
    },
  };
  return { ctx, h };
}

// Ensure the scratch service exists (idempotent) and return its summary.
export async function ensureService(h) {
  const existing = await h.api(`/api/services/${CONFIG.svc}`);
  if (existing.status === 200) return existing.data;
  const compose = 'services:\n  web:\n    image: nginx:alpine\n    ports:\n      - "18081:80"\n';
  const r = await h.api('/api/services', { method: 'POST', body: { name: CONFIG.svc, compose } });
  if (r.status !== 200) throw new Error(`create ${CONFIG.svc}: ${JSON.stringify(r.data).slice(0, 200)}`);
  await h.api(`/api/services/${CONFIG.svc}/actions`, { method: 'POST', body: { action: 'up' } });
  return r.data;
}

export async function deleteService(h, name) {
  await h.api(`/api/services/${name}/actions`, { method: 'POST', body: { action: 'down' } }).catch(() => {});
  await sleep(2500);
  await h.api(`/api/services/${name}`, { method: 'DELETE', body: { force: true } }).catch(() => {});
}
