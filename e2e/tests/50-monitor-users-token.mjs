import { CONFIG, sleep } from '../lib/harness.mjs';

export default async function (h) {
  const { ctx, page } = h;
  const svc = CONFIG.svc;

  // ============ global monitor panel: notifiers ============
  await h.goto('/monitor');
  await sleep(1500);

  // add a webhook notifier
  let r = await page.evaluate(async () => {
    window.__clickText('add');
    await new Promise(r => setTimeout(r, 800));
    const mp = window.__deep('ddm-monitor-panel');
    const sr = mp.shadowRoot;
    const idI = [...sr.querySelectorAll('input')].find(i => i.placeholder === 'id' && i.offsetParent);
    if (!idI) return { err: 'no id input' };
    window.__setVal(idI, 'e2e-hook');
    const sel = [...sr.querySelectorAll('select')].find(s => s.offsetParent);
    if (sel) {
      // drive the component state directly — reliable regardless of event timing
      mp.form = { ...mp.form, type: 'webhook' };
      await new Promise(r => setTimeout(r, 800));
    }
    // webhook fields: url (secret) + headers textarea — find url input by placeholder or order
    const inputs = [...sr.querySelectorAll('input, textarea')].filter(i => i.offsetParent && i !== idI && i.type !== 'checkbox' && i.type !== 'number');
    const urlI = inputs.find(i => /ntfy|url|http/i.test(i.placeholder || '')) || inputs[0];
    if (urlI) window.__setVal(urlI, 'http://127.0.0.1:9/e2e-hook');
    await new Promise(r => setTimeout(r, 300));
    const save = [...sr.querySelectorAll('button')].find(b => b.textContent.trim() === 'save' && b.offsetParent);
    if (save) save.click();
    await new Promise(r => setTimeout(r, 2000));
    return { ok: !!save, msg: sr.textContent.slice(0, 300) };
  });
  let nots = await h.api('/api/monitoring/notifiers');
  const hasHook = JSON.stringify(nots.data).includes('e2e-hook');
  ctx.check('monitor: add notifier via form', r.ok === true && hasHook, `api=${JSON.stringify(nots.data).slice(0, 120)}`);

  // edit it (change url)
  if (hasHook) {
    r = await page.evaluate(async () => {
      const mp = window.__deep('ddm-monitor-panel');
      const rows = [...mp.shadowRoot.querySelectorAll('tr')];
      const row = rows.find(x => x.textContent.includes('e2e-hook'));
      const edit = row && [...row.querySelectorAll('button')].find(b => b.textContent.trim() === 'edit');
      if (!edit) return { err: 'no edit btn' };
      edit.click();
      await new Promise(r => setTimeout(r, 800));
      const sr = mp.shadowRoot;
      const inputs = [...sr.querySelectorAll('input, textarea')].filter(i => i.offsetParent && i.type !== 'checkbox' && i.type !== 'number');
      const urlI = inputs.find(i => /ntfy|url|http/i.test(i.placeholder || '')) || inputs[inputs.length - 1];
      if (urlI) window.__setVal(urlI, 'http://127.0.0.1:9/e2e-hook-v2');
      await new Promise(r => setTimeout(r, 300));
      const save = [...sr.querySelectorAll('button')].find(b => b.textContent.trim() === 'save' && b.offsetParent);
      if (save) save.click();
      await new Promise(r => setTimeout(r, 2000));
      return { ok: !!save };
    });
    nots = await h.api('/api/monitoring/notifiers');
    ctx.check('monitor: edit notifier', r.ok === true && JSON.stringify(nots.data).includes('e2e-hook'), '');

    // test button — endpoint unreachable, expect graceful error message not crash
    r = await page.evaluate(async () => {
      const mp = window.__deep('ddm-monitor-panel');
      const rows = [...mp.shadowRoot.querySelectorAll('tr')];
      const row = rows.find(x => x.textContent.includes('e2e-hook'));
      const test = row && [...row.querySelectorAll('button')].find(b => b.textContent.trim() === 'test');
      if (!test) return { err: 'no test btn' };
      test.click();
      await new Promise(r => setTimeout(r, 4000));
      return { ok: true, msg: mp.shadowRoot.textContent.slice(0, 300) };
    });
    ctx.check('monitor: test button runs (graceful on unreachable)', r.ok === true, (r.msg || '').slice(0, 100));

    // delete
    h.ctx.expectDialog();
    r = await page.evaluate(async () => {
      const mp = window.__deep('ddm-monitor-panel');
      const rows = [...mp.shadowRoot.querySelectorAll('tr')];
      const row = rows.find(x => x.textContent.includes('e2e-hook'));
      const del = row && [...row.querySelectorAll('button')].find(b => b.textContent.trim() === 'delete');
      if (!del) return { err: 'no delete btn' };
      del.click();
      await new Promise(r => setTimeout(r, 1500));
      return { ok: true };
    });
    await sleep(800);
    nots = await h.api('/api/monitoring/notifiers');
    ctx.check('monitor: delete notifier', r.ok === true && !JSON.stringify(nots.data).includes('e2e-hook'), '');
  } else {
    ctx.fail('monitor: edit/test/delete skipped (add failed)');
  }

  // ============ service monitoring config ============
  await h.goto(`/service/${svc}`);
  await sleep(1000);
  await h.tab('Monitoring');
  r = await page.evaluate(async () => {
    const sm = window.__deep('ddm-service-monitoring');
    const edit = [...sm.shadowRoot.querySelectorAll('button')].find(b => b.textContent.includes('edit config'));
    if (edit) edit.click();
    await new Promise(r => setTimeout(r, 700));
    const save = [...sm.shadowRoot.querySelectorAll('button')].find(b => b.textContent.trim() === 'save' && b.offsetParent);
    if (save) save.click();
    await new Promise(r => setTimeout(r, 1500));
    return { ok: !!save };
  });
  ctx.check('monitoring: service edit config + save', r.ok === true);

  // ============ users ============
  await h.goto('/users');
  await sleep(1500);
  const uname = 'e2e-ui-user';
  await h.api('/api/users', { method: 'DELETE', body: {} }).catch(() => {});
  await page.evaluate(async (n) => {
    const tok = sessionStorage.getItem('ddm_token');
    await fetch('/api/users/' + n, { method: 'DELETE', headers: { Authorization: 'Bearer ' + tok } }).catch(() => {});
  }, uname);
  await sleep(500);

  // add via form
  r = await page.evaluate(async (n) => {
    window.__clickText('add user') || window.__clickText('add');
    await new Promise(r => setTimeout(r, 700));
    const uu = window.__deep('ddm-users');
    const sr = uu.shadowRoot;
    const nameI = [...sr.querySelectorAll('input')].find(i => i.placeholder === 'name' && i.offsetParent);
    const pwI = [...sr.querySelectorAll('input[type=password]')].find(i => i.offsetParent) ||
               [...sr.querySelectorAll('input')].find(i => i.placeholder === 'password' && i.offsetParent);
    if (!nameI || !pwI) return { err: 'form inputs missing' };
    window.__setVal(nameI, n);
    window.__setVal(pwI, 'E2ePass123!');
    await new Promise(r => setTimeout(r, 300));
    const add = [...sr.querySelectorAll('button')].find(b => /add|create|save/i.test(b.textContent) && b.offsetParent);
    if (add) add.click();
    await new Promise(r => setTimeout(r, 2000));
    return { ok: !!add, msg: sr.textContent.slice(0, 200) };
  }, uname);
  let users = await h.api('/api/users');
  ctx.check('users: add via form', r.ok === true && JSON.stringify(users.data).includes(uname), (r.msg || '').slice(0, 80));

  if (JSON.stringify(users.data).includes(uname)) {
    // select the user (click name link) -> detail card shows roles/policy/access editors
    r = await page.evaluate(async (n) => {
      const uu = window.__deep('ddm-users');
      const link = [...uu.shadowRoot.querySelectorAll('a')].find(a => a.textContent.trim() === n);
      if (!link) return { err: 'user link missing' };
      link.click();
      await new Promise(r => setTimeout(r, 900));
      const rolesIn = uu.shadowRoot.querySelector('#roles-in');
      if (!rolesIn) return { err: 'no roles input' };
      window.__setVal(rolesIn, 'operator,viewer');
      await new Promise(r => setTimeout(r, 300));
      // the save button in the same .row as #roles-in
      const row = rolesIn.closest('.row');
      const sv = row && [...row.querySelectorAll('button')].find(b => b.textContent.trim() === 'save');
      if (!sv) return { err: 'no roles save btn' };
      sv.click();
      await new Promise(r => setTimeout(r, 1800));
      return { ok: true };
    }, uname);
    users = await h.api('/api/users');
    const uStr = JSON.stringify(users.data);
    const roleOk = uStr.includes(uname) && /"roles":\["operator","viewer"\]|"roles":\["viewer","operator"\]/.test(uStr);
    ctx.check('users: edit roles + save', r.ok === true && roleOk, uStr.match(new RegExp('"name":"' + uname + '"[^}]*'))?.[0]?.slice(0, 120) || '');

    // compose policy select + save
    r = await page.evaluate(async () => {
      const uu = window.__deep('ddm-users');
      const sel = uu.shadowRoot.querySelector('#policy-sel');
      if (!sel) return { err: 'no policy sel' };
      sel.value = 'strict';
      sel.dispatchEvent(new Event('change', { bubbles: true }));
      await new Promise(r => setTimeout(r, 300));
      const row = sel.closest('.row');
      const sv = row && [...row.querySelectorAll('button')].find(b => b.textContent.trim() === 'save');
      if (sv) sv.click();
      await new Promise(r => setTimeout(r, 1500));
      return { ok: !!sv };
    });
    users = await h.api('/api/users');
    ctx.check('users: compose policy save', r.ok === true && JSON.stringify(users.data).includes('strict'), '');

    // feature checkbox toggle
    r = await page.evaluate(async () => {
      const uu = window.__deep('ddm-users');
      const cb = [...uu.shadowRoot.querySelectorAll('input[type=checkbox]')].find(c => {
        const l = c.closest('label');
        return l && /run_commands/.test(l.textContent);
      });
      if (!cb) return { err: 'no feature cb' };
      cb.click();
      await new Promise(r => setTimeout(r, 1500));
      return { ok: true };
    });
    users = await h.api('/api/users');
    ctx.check('users: feature toggle', r.ok === true, '');

    // access rules textarea + save rules
    r = await page.evaluate(async () => {
      const uu = window.__deep('ddm-users');
      const ta = uu.shadowRoot.querySelector('#access-ta');
      if (!ta) return { err: 'no access ta' };
      window.__setVal(ta, 'deny exact:traefik\nallow glob:*');
      await new Promise(r => setTimeout(r, 300));
      const sv = [...uu.shadowRoot.querySelectorAll('button')].find(b => /save rules/.test(b.textContent) && b.offsetParent);
      if (sv) sv.click();
      await new Promise(r => setTimeout(r, 1500));
      return { ok: !!sv };
    });
    users = await h.api('/api/users');
    ctx.check('users: access rules save', r.ok === true && JSON.stringify(users.data).includes('deny'), '');

    // password change via prompt
    h.ctx.expectDialog('E2eNewPass456!');
    r = await page.evaluate(async (n) => {
      const uu = window.__deep('ddm-users');
      const rows = [...uu.shadowRoot.querySelectorAll('tr')];
      const row = rows.find(x => x.textContent.includes(n));
      const btn = row && [...row.querySelectorAll('button')].find(b => b.textContent.trim() === 'pw');
      if (!btn) return { err: 'no pw btn' };
      btn.click();
      await new Promise(r => setTimeout(r, 2000));
      return { ok: true, msg: uu.shadowRoot.textContent.slice(0, 200) };
    }, uname);
    const loginNew = await page.evaluate(async (n) => {
      const resp = await fetch('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: n, password: 'E2eNewPass456!' }) });
      return resp.status;
    }, uname);
    ctx.check('users: password change via prompt', r.ok === true && loginNew === 200, `login=${loginNew}`);

    // delete via × (confirm dialog)
    h.ctx.expectDialog();
    r = await page.evaluate(async (n) => {
      const uu = window.__deep('ddm-users');
      const rows = [...uu.shadowRoot.querySelectorAll('tr')];
      const row = rows.find(x => x.textContent.includes(n));
      const btn = row && [...row.querySelectorAll('button')].find(b => b.textContent.trim() === '×');
      if (!btn) return { err: 'no delete btn' };
      btn.click();
      await new Promise(r => setTimeout(r, 1500));
      return { ok: true };
    }, uname);
    await sleep(800);
    users = await h.api('/api/users');
    ctx.check('users: delete via ×', r.ok === true && !JSON.stringify(users.data).includes(uname), '');
  }

  // ============ MCP token ============
  await h.goto('/token');
  await sleep(1500);
  r = await page.evaluate(async () => {
    const ok = window.__clickText('generate token');
    await new Promise(r => setTimeout(r, 3000));
    const tt = window.__deep('ddm-token');
    const txt = tt ? tt.shadowRoot.textContent : '';
    const m = txt.match(/eyJ[A-Za-z0-9_\-\.]+/);
    const copyBtn = [...tt.shadowRoot.querySelectorAll('button')].find(b => /copy/i.test(b.textContent));
    if (copyBtn) copyBtn.click();
    return { clicked: ok, hasToken: !!m, token: m ? m[0] : null, copyBtn: !!copyBtn };
  });
  ctx.check('token: generate + display + copy', r.clicked === true && r.hasToken === true && r.copyBtn === true, '');

  // scoped token: limit to e2e-svc only -> other service denied
  r = await page.evaluate(async (svcName) => {
    const tt = window.__deep('ddm-token');
    const sr = tt.shadowRoot;
    // enable service scoping
    const scopeCb = [...sr.querySelectorAll('input[type=checkbox]')].find(c => {
      const l = c.closest('label');
      return l && /limit to services/i.test(l.textContent);
    });
    if (!scopeCb) return { err: 'no scope checkbox' };
    scopeCb.click();
    await new Promise(r => setTimeout(r, 600));
    // check only our service
    const boxes = [...sr.querySelectorAll('input[type=checkbox]')];
    for (const b of boxes) {
      const l = b.closest('label');
      const on = l && l.textContent.includes(svcName);
      if (on && !b.checked) b.click();
      if (!on && b.checked && l && !/limit to/.test(l.textContent)) b.click();
    }
    await new Promise(r => setTimeout(r, 400));
    window.__clickText('generate token');
    await new Promise(r => setTimeout(r, 3000));
    const txt = tt.shadowRoot.textContent;
    const m = txt.match(/eyJ[A-Za-z0-9_\-\.]+/g);
    return { tokens: m ? m.slice(-1)[0] : null };
  }, svc);
  if (r.tokens) {
    const scoped = await page.evaluate(async (tok) => {
      const mine = await fetch('/api/services/' + 'e2e-svc', { headers: { Authorization: 'Bearer ' + tok } });
      const other = await fetch('/api/services/traefik', { headers: { Authorization: 'Bearer ' + tok } });
      return { mine: mine.status, other: other.status };
    }, r.tokens);
    ctx.check('token: scoped token narrows access', scoped.mine === 200 && scoped.other !== 200, JSON.stringify(scoped));
  } else {
    ctx.fail('token: scoped token generation', 'no token issued');
  }
}
