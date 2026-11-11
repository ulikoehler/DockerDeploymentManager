// Batch-6 coverage: execution cancel, meta edit, version footer,
// sort/filter additions, dirty-navigation guard, log download.
import { CONFIG, ensureService, sleep } from '../lib/harness.mjs';

const sleepItem = {
  title: 'e2e-sleep',
  description: '',
  work_dir: '/tmp',
  icon: '',
  parameters: [],
  button_label: 'Run',
  on_host: true,
  command_sequence: [
    { program: '/bin/sleep', args: [{ type: 'value', value: '30' }] },
  ],
};

export default async function (h) {
  const { page } = h;
  const ctx = h.ctx;
  await ensureService(h);

  // --- health reports version ------------------------------------------
  const health = await h.api('/api/health');
  ctx.check('health: version reported', !!health.data?.version || !!health.version,
    JSON.stringify(health.data ?? health).slice(0, 80));

  // --- execution cancel --------------------------------------------------
  // add a throwaway section with a 30s sleep, run it, cancel it.
  const secsBefore = await h.api('/api/commands/sections');
  const secs = secsBefore.data ?? [];
  let idx = secs.findIndex((s) => s.title === 'e2e-cancel');
  if (idx < 0) {
    const add = await h.api('/api/commands/sections', {
      method: 'POST',
      body: { op: 'add', section: { title: 'e2e-cancel', items: [sleepItem] } },
    });
    ctx.check('exec cancel: section added', add.status === 200, `status=${add.status}`);
    const secs2 = await h.api('/api/commands/sections');
    idx = (secs2.data ?? []).findIndex((s) => s.title === 'e2e-cancel');
  }
  ctx.check('exec cancel: section present', idx >= 0, `idx=${idx}`);

  let execId = null;
  if (idx >= 0) {
    const run = await h.api(`/api/commands/${idx}/0`, { method: 'POST', body: {} });
    execId = run.data?.execution_id ?? run.data?.id ?? run.execution_id;
    ctx.check('exec cancel: sleep execution started', !!execId, JSON.stringify(run.data).slice(0, 100));
    await sleep(800);
    const cancel = await h.api(`/api/executions/${execId}/cancel`, { method: 'POST' });
    ctx.check('exec cancel: cancel accepted', cancel.status === 200, `status=${cancel.status} ${JSON.stringify(cancel.data).slice(0, 80)}`);
    // wait for the execution to actually finish as failed/cancelled
    let fin = null;
    for (let i = 0; i < 20; i++) {
      const e = await h.api(`/api/executions/${execId}`);
      fin = e.data;
      if (fin?.finished_at) break;
      await sleep(500);
    }
    ctx.check('exec cancel: execution terminated', !!fin?.finished_at, `finished=${fin?.finished_at}`);
    ctx.check('exec cancel: marked unsuccessful', fin?.success === false, `success=${fin?.success}`);
  }

  // cleanup section
  if (idx >= 0) {
    await h.api('/api/commands/sections', {
      method: 'POST', body: { op: 'delete', index: idx },
    }).catch(() => {});
  }

  // --- meta description edit ---------------------------------------------
  const svc = await h.api(`/api/services/${CONFIG.svc}`);
  const meta = svc.data?.meta ?? {};
  const desc = `e2e-desc-${Date.now()}`;
  const put = await h.api(`/api/services/${CONFIG.svc}/meta`, {
    method: 'PUT',
    body: { ...meta, description: desc },
  });
  ctx.check('meta: PUT accepted', put.status === 200, `status=${put.status} ${JSON.stringify(put.data).slice(0, 80)}`);
  const svc2 = await h.api(`/api/services/${CONFIG.svc}`);
  ctx.check('meta: description persisted', svc2.data?.meta?.description === desc,
    `got=${svc2.data?.meta?.description}`);
  await h.api(`/api/services/${CONFIG.svc}/meta`, {
    method: 'PUT', body: { ...meta },
  }).catch(() => {});

  // --- UI: version footer, sort select, audit filter, log download -------
  await h.goto('/');
  await sleep(1500);
  const foot = await page.evaluate(() => document.querySelector('ddm-app')?.shadowRoot?.querySelector('footer')?.textContent ?? '');
  ctx.check('ui: version footer', /DDM v/.test(foot), foot.trim());

  const listTxt = await h.compText('ddm-service-list');
  ctx.check('ui: sort select present', /sort: name/.test(listTxt));

  await h.goto('/audit');
  await sleep(1200);
  const auditHasFilter = await page.evaluate(() => {
    const find = (root, tag) => {
      for (const el of root.querySelectorAll('*')) {
        if (el.shadowRoot) {
          const f = find(el.shadowRoot, tag);
          if (f) return f;
        }
        if (el.tagName === tag) return el;
      }
      return null;
    };
    const app = document.querySelector('ddm-app');
    const a = find(app?.shadowRoot ?? document, 'DDM-AUDIT');
    return !!a?.shadowRoot?.querySelector('input[placeholder*="filter"]');
  });
  ctx.check('ui: audit filter input', auditHasFilter);

  // log viewer download button
  await h.goto(`/service/${CONFIG.svc}`);
  await sleep(1500);
  await h.tab('Logs');
  await sleep(1500);
  const hasDl = await page.evaluate(() => {
    const deep = (root, sel) => {
      for (const el of root.querySelectorAll('*')) {
        if (el.shadowRoot) {
          const f = deep(el.shadowRoot, sel);
          if (f) return f;
        }
        if (el.matches?.(sel)) return el;
      }
      return null;
    };
    const app = document.querySelector('ddm-app');
    return !!deep(app.shadowRoot ?? document, 'ddm-log-viewer');
  });
  const dlBtn = await page.evaluate(() => {
    const find = (root) => {
      for (const el of root.querySelectorAll('*')) {
        if (el.shadowRoot) {
          const f = find(el.shadowRoot);
          if (f) return f;
        }
        if (el.tagName === 'DDM-LOG-VIEWER') return el;
      }
      return null;
    };
    const lv = find(document.querySelector('ddm-app')?.shadowRoot ?? document);
    return !!lv?.shadowRoot?.querySelector('button');
  });
  ctx.check('ui: log viewer mounted', hasDl && dlBtn);

  // --- dirty guard: edit compose, navigate away, expect confirm -----------
  await h.tab('Compose');
  await sleep(1500);
  const dirtied = await page.evaluate(() => {
      const find = (root, tag) => {
        for (const el of root.querySelectorAll('*')) {
          if (el.shadowRoot) {
            const f = find(el.shadowRoot, tag);
            if (f) return f;
          }
          if (el.tagName === tag) return el;
        }
        return null;
      };
      const app = document.querySelector('ddm-app');
      const ed = find(app.shadowRoot ?? document, 'DDM-COMPOSE-EDITOR');
      const cm = ed?.shadowRoot?.querySelector('ddm-code-editor');
      if (!cm?.setDoc) return 'no-editor';
      cm.setDoc('services:\n  dirty-test: {}\n');
      return 'ok';
    });
  ctx.check('dirty: compose editor dirtyable', dirtied === 'ok', String(dirtied));
  await sleep(400);
  await page.evaluate(() => { location.hash = '#/executions'; });
  await sleep(900);
  const dlg = await page.evaluate(() => !!document.getElementById('ddm-dialog-root')?.querySelector('.modal'));
  ctx.check('dirty: nav guard dialog appears', dlg);
  if (dlg) {
    // cancel → stay on the service page
    await page.evaluate(() => {
      const root = document.getElementById('ddm-dialog-root');
      const cancel = [...root.querySelectorAll('button')].find(b => /cancel/i.test(b.textContent));
      cancel?.click();
    });
    await sleep(700);
    const still = await page.evaluate(() => location.hash.includes(`/service/`));
    ctx.check('dirty: hash unchanged after cancel', still, await page.evaluate(() => location.hash));
    // confirm leave → navigates
    await page.evaluate(() => { location.hash = '#/executions'; });
    await sleep(900);
    await h.answerDialog();
    await sleep(700);
    const left = await page.evaluate(() => !location.hash.includes('/service/'));
    ctx.check('dirty: confirm leaves page', left, await page.evaluate(() => location.hash));
  }
  // reload to drop the dirty state (no save happened)
  await page.reload({ waitUntil: 'networkidle0' });
  await sleep(1200);
}
