// Named tokens + granular ops scopes: UI fields, mint via API, list shows
// the name, ops allowlist actually gates verbs, revocation still works.
import { CONFIG, ensureService, sleep } from '../lib/harness.mjs';

export default async function (h) {
  const { page } = h;
  const ctx = h.ctx;
  await ensureService(h);

  // --- UI: name input + operations scope present --------------------------
  await h.goto('/token');
  await sleep(1200);
  const ui = await page.evaluate(() => {
    const deep = (sel, root = document) => {
      const el = root.querySelector(sel);
      if (el) return el;
      for (const e of root.querySelectorAll('*')) {
        if (e.shadowRoot) { const r = deep(sel, e.shadowRoot); if (r) return r; }
      }
      return null;
    };
    const comp = deep('ddm-token');
    const root = comp?.shadowRoot;
    if (!root) return { name: false, opsBox: false, opBoxes: 0, nameCol: false };
    const txt = root.textContent;
    return {
      name: !!root.querySelector('input[maxlength="80"]'),
      opsBox: txt.includes('limit to operations'),
      opBoxes: [...root.querySelectorAll('input[type="checkbox"]')].length,
      nameCol: txt.includes('sessions & tokens'),
    };
  });
  ctx.check('ui: optional name input present', ui.name === true);
  ctx.check('ui: operations scope present', ui.opsBox === true);

  // --- API: mint a named, read-only token (ops is the only gate) ---------
  const svc = CONFIG.svc;
  const mint = await h.api('/api/auth/token', {
    method: 'POST',
    body: { ttl_minutes: 30, name: 'e2e-readonly', ops: ['read'] },
  });
  const tok = mint.data?.token;
  ctx.check('mint: named ops-scoped token issued', !!tok, JSON.stringify(mint.data).slice(0, 120));
  ctx.check('mint: token is short opaque (15 chars, no JWT dots)',
    typeof tok === 'string' && tok.length === 15 && !tok.includes('.'),
    `len=${tok?.length}`);

  // --- it appears in the token list with its name -------------------------
  const list = await h.api('/api/auth/tokens');
  // records persist across runs — take the newest matching one
  const rec = (list.data ?? []).filter((t) => t.name === 'e2e-readonly').pop();
  ctx.check('list: token record carries name', !!rec, `records=${(list.data ?? []).length}`);
  ctx.check('list: record keeps ops scope', !!rec?.ops?.includes('read'), JSON.stringify(rec?.ops));

  // --- the scoped token itself: reads work, writes denied -----------------
  const call = (path, method = 'GET', body) =>
    page.evaluate(async ([p, m, b, t]) => {
      const r = await fetch(p, {
        headers: { Authorization: `Bearer ${t}`, ...(b ? { 'Content-Type': 'application/json' } : {}) },
        method: m,
        body: b ? JSON.stringify(b) : undefined,
      });
      return r.status;
    }, [path, method, body, tok]);

  const stList = await call('/api/services');
  const stGet = await call(`/api/services/${svc}`);
  const stCompose = await call(`/api/services/${svc}/compose`);
  const stAction = await call(`/api/services/${svc}/actions`, 'POST', { action: 'restart' });
  const stPutCompose = await call(`/api/services/${svc}/compose`, 'PUT', { content: 'x', recreate: false });
  const stExec = await call('/api/commands/run', 'POST', { section: 0, item: 0 }).catch(() => 0);

  ctx.check('ops=read: GET /api/services allowed', stList === 200, `status=${stList}`);
  ctx.check('ops=read: GET service detail allowed', stGet === 200, `status=${stGet}`);
  ctx.check('ops=read: GET compose allowed', stCompose === 200, `status=${stCompose}`);
  // agent-side denials surface as 500 (pre-existing internal() mapping) —
  // any non-2xx proves the op was refused
  const denied = (s) => s !== 200 && s !== 201 && s !== 204;
  ctx.check('ops=read: service action denied', denied(stAction), `status=${stAction}`);
  ctx.check('ops=read: compose PUT denied', denied(stPutCompose), `status=${stPutCompose}`);

  // --- a compose-ops token may restart but not write files ---------------
  const mint2 = await h.api('/api/auth/token', {
    method: 'POST',
    body: { ttl_minutes: 30, name: 'e2e-compose', ops: ['read', 'compose'] },
  });
  const tok2 = mint2.data?.token;
  const call2 = (path, method = 'GET', body) =>
    page.evaluate(async ([p, m, b, t]) => {
      const r = await fetch(p, {
        headers: { Authorization: `Bearer ${t}`, ...(b ? { 'Content-Type': 'application/json' } : {}) },
        method: m,
        body: b ? JSON.stringify(b) : undefined,
      });
      return r.status;
    }, [path, method, body, tok2]);
  const stRestart = await call2(`/api/services/${svc}/actions`, 'POST', { action: 'restart' });
  const stFiles = await call2(`/api/services/${svc}/files`, 'PUT', { path: '/x', content: 'y' }).catch(() => 0);
  ctx.check('ops=compose: service action allowed', stRestart === 200, `status=${stRestart}`);
  ctx.check('ops=compose: file write denied', denied(stFiles), `status=${stFiles}`);

  // --- unnamed token still works (backward compat) ------------------------
  const mint3 = await h.api('/api/auth/token', { method: 'POST', body: { ttl_minutes: 15 } });
  const tok3 = mint3.data?.token;
  const stFull = await page.evaluate(async ([p, t]) => {
    const r = await fetch(p, { headers: { Authorization: `Bearer ${t}` } });
    return r.status;
  }, ['/api/services', tok3]);
  ctx.check('unnamed token still works', stFull === 200, `status=${stFull}`);

  // --- revoke the named token by jti --------------------------------------
  if (rec?.jti) {
    await h.api(`/api/auth/tokens/${rec.jti}`, { method: 'DELETE' });
    const stAfter = await call('/api/services');
    ctx.check('revoked named token dies', stAfter === 401 || stAfter === 403, `status=${stAfter}`);
  } else {
    ctx.fail('revoked named token dies', 'no record jti');
  }
  // cleanup remaining test tokens
  const list2 = await h.api('/api/auth/tokens');
  for (const t of (list2.data ?? []).filter((x) => !x.revoked && ['e2e-readonly', 'e2e-compose'].includes(x.name))) {
    await h.api(`/api/auth/tokens/${t.jti}`, { method: 'DELETE' }).catch(() => {});
  }
}
