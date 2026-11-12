// Token TTL: unit selector in UI + up-to-10-years lifetimes via API.
import { CONFIG, ensureService, sleep } from '../lib/harness.mjs';

const TEN_YEARS_MIN = 5_256_000;

export default async function (h) {
  const { page } = h;
  const ctx = h.ctx;
  await ensureService(h);

  // --- UI: lifetime has a unit selector incl. years ----------------------
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
    if (!root) return { sel: false, opts: [], presets: [] };
    const sel = root.querySelector('select');
    return {
      sel: !!sel,
      opts: sel ? [...sel.options].map((o) => o.value) : [],
      presets: [...root.querySelectorAll('button')].map((b) => b.textContent.trim()).filter((t) => /^[\ddhymo]+$/.test(t)),
    };
  });
  ctx.check('ttl ui: unit selector present', ui.sel === true);
  ctx.check('ttl ui: minutes→years units', ['minutes', 'hours', 'days', 'months', 'years'].every((u) => ui.opts.includes(u)),
    ui.opts.join(','));
  ctx.check('ttl ui: presets incl. 10y', ui.presets.includes('10y'), ui.presets.join(','));

  // --- API: explicit 10-year token ----------------------------------------
  const t0 = await h.api('/api/auth/token', {
    method: 'POST',
    body: { ttl_minutes: TEN_YEARS_MIN },
  });
  const exp1 = t0.data?.expires_at ?? 0;
  const delta1 = exp1 - Math.floor(Date.now() / 1000);
  ctx.check('ttl api: 10y token issued', !!t0.data?.token && delta1 > TEN_YEARS_MIN * 60 - 120,
    `delta=${Math.round(delta1 / 86400)}d`);

  // --- API: absurd value clamps at 10 years -------------------------------
  const t1 = await h.api('/api/auth/token', {
    method: 'POST',
    body: { ttl_minutes: Number.MAX_SAFE_INTEGER },
  });
  const delta2 = (t1.data?.expires_at ?? 0) - Math.floor(Date.now() / 1000);
  ctx.check('ttl api: huge ttl clamps to 10y', delta2 <= TEN_YEARS_MIN * 60 + 120,
    `delta=${Math.round(delta2 / 86400)}d`);

  // cleanup: revoke the minted tokens so they don't linger in the list
  const list = await h.api('/api/auth/tokens');
  for (const t of (list.data ?? []).filter((x) => !x.revoked && x.jti)) {
    await h.api(`/api/auth/tokens/${t.jti}`, { method: 'DELETE' }).catch(() => {});
  }
}
