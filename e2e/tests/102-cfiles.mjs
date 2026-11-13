// Container & volume file transfer: list endpoints, raw/tar/targz
// download+upload against a real container fs and a compose named volume,
// ops-scope enforcement, and the Files-tab UI card.
import { CONFIG, ensureService, sleep } from '../lib/harness.mjs';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export default async function (h) {
  const { page } = h;
  const ctx = h.ctx;
  const svc = CONFIG.svc;
  await ensureService(h);

  // give the scratch service a named volume so project-volume listing works
  const compose = `services:\n  web:\n    image: nginx:alpine\n    volumes:\n      - data:/data\n    ports:\n      - "18081:80"\nvolumes:\n  data:\n`;
  const put = await h.api(`/api/services/${svc}/compose`, {
    method: 'PUT', body: { content: compose },
  });
  ctx.check('compose: add named volume accepted', put.status === 200, `status=${put.status}`);
  await h.api(`/api/services/${svc}/actions`, { method: 'POST', body: { action: 'up' } });
  await sleep(4000);

  // --- listing endpoints --------------------------------------------------
  const containers = await h.api(`/api/services/${svc}/containers`);
  const clist = containers.data ?? [];
  ctx.check('containers: project list non-empty', clist.length > 0, `n=${clist.length}`);
  const cid = clist[0]?.id;
  ctx.check('containers: entry has id+name', !!cid && !!clist[0]?.name, JSON.stringify(clist[0]).slice(0, 120));

  const volumes = await h.api(`/api/services/${svc}/volumes`);
  const vlist = volumes.data ?? [];
  const vol = vlist.find((v) => v.endsWith('_data')) ?? vlist[0];
  ctx.check('volumes: project list has the data volume', !!vol, JSON.stringify(vlist));

  // raw fetch helpers inside the page (binary-safe, bearer from session)
  const xfer = (method, url, body) => page.evaluate(async ([m, u, b64]) => {
    const tok = sessionStorage.getItem('ddm_token');
    const bodyBytes = b64 ? Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)) : undefined;
    const r = await fetch(u, {
      method: m,
      headers: {
        Authorization: `Bearer ${tok}`,
        ...(bodyBytes ? { 'Content-Type': 'application/octet-stream' } : {}),
      },
      body: bodyBytes,
    });
    const buf = await r.arrayBuffer();
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i += 8192) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
    }
    return {
      status: r.status,
      text: new TextDecoder().decode(buf),
      b64: btoa(bin),
      len: buf.byteLength,
      ct: r.headers.get('content-type'),
    };
  }, [method, url, body ? Buffer.from(body).toString('base64') : null]);

  // --- container download: raw file --------------------------------------
  const dlRaw = await xfer('GET', `/api/services/${svc}/containers/${cid}/files?path=/etc/nginx/nginx.conf&format=raw`);
  ctx.check('container dl raw: 200 + nginx.conf content',
    dlRaw.status === 200 && dlRaw.text.includes('nginx'), `status=${dlRaw.status} len=${dlRaw.len}`);

  // --- container download: targz of a directory --------------------------
  const dlTg = await xfer('GET', `/api/services/${svc}/containers/${cid}/files?path=/etc/nginx/conf.d&format=targz`);
  ctx.check('container dl targz: 200 + gzip magic',
    dlTg.status === 200 && dlTg.len > 100, `status=${dlTg.status} len=${dlTg.len}`);
  const tgzPath = path.join(os.tmpdir(), 'ddm-e2e-conf.tgz');
  fs.writeFileSync(tgzPath, Buffer.from(dlTg.b64, 'base64'));
  // verify it is a real gzip tar listing default.conf
  const list = execFileSync('tar', ['-tzf', tgzPath], { encoding: 'utf8' });
  ctx.check('container dl targz: valid archive with entries', list.includes('default.conf'), list.slice(0, 80));

  // --- container upload: raw single file ----------------------------------
  const payload = `ddm-e2e-${Date.now()}`;
  const upRaw = await xfer('PUT', `/api/services/${svc}/containers/${cid}/files?path=/tmp/ddm-e2e.txt&format=raw`, payload);
  ctx.check('container ul raw: accepted', upRaw.status === 200, `status=${upRaw.status} ${upRaw.text.slice(0, 80)}`);
  const dlBack = await xfer('GET', `/api/services/${svc}/containers/${cid}/files?path=/tmp/ddm-e2e.txt&format=raw`);
  ctx.check('container ul raw: round-trip content', dlBack.text === payload, `got=${dlBack.text}`);

  // --- volume download + upload -------------------------------------------
  const vUp = await xfer('PUT', `/api/services/${svc}/volumes/${vol}/files?path=/hello.txt&format=raw`, 'volume-hello');
  ctx.check('volume ul raw: accepted', vUp.status === 200, `status=${vUp.status} ${vUp.text.slice(0, 80)}`);
  const vDl = await xfer('GET', `/api/services/${svc}/volumes/${vol}/files?path=/hello.txt&format=raw`);
  ctx.check('volume dl raw: round-trip', vDl.status === 200 && vDl.text === 'volume-hello', `status=${vDl.status} got=${vDl.text}`);

  // targz upload into a subdir, then read back the file raw
  const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'ddm-vol-'));
  fs.mkdirSync(path.join(stage, 'payload'));
  fs.writeFileSync(path.join(stage, 'payload', 'inside.txt'), 'inside-the-volume');
  const arc = path.join(os.tmpdir(), 'ddm-e2e-vol.tar.gz');
  execFileSync('tar', ['-czf', arc, '-C', stage, 'payload']);
  const arcB64 = fs.readFileSync(arc).toString('base64');
  const vUpTg = await page.evaluate(async ([u, b64]) => {
    const tok = sessionStorage.getItem('ddm_token');
    const r = await fetch(u, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/octet-stream' },
      body: Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)),
    });
    return { status: r.status, text: await r.text() };
  }, [`/api/services/${svc}/volumes/${vol}/files?path=/restore&format=targz`, arcB64]);
  ctx.check('volume ul targz: accepted', vUpTg.status === 200, `status=${vUpTg.status} ${vUpTg.text.slice(0, 80)}`);
  const vDl2 = await xfer('GET', `/api/services/${svc}/volumes/${vol}/files?path=/restore/payload/inside.txt&format=raw`);
  ctx.check('volume ul targz: extracted file readable', vDl2.text === 'inside-the-volume', `got=${vDl2.text}`);

  // --- ops scope: read-only token can download but not upload -------------
  const mint = await h.api('/api/auth/token', { method: 'POST', body: { ttl_minutes: 15, ops: ['read'] } });
  const tok = mint.data?.token;
  ctx.check('ops token minted', !!tok);
  const scoped = (method, url, body) => page.evaluate(async ([m, u, b, t]) => {
    const r = await fetch(u, {
      method: m,
      headers: { Authorization: `Bearer ${t}`, ...(b ? { 'Content-Type': 'application/octet-stream' } : {}) },
      body: b ? Uint8Array.from(atob(b), (c) => c.charCodeAt(0)) : undefined,
    });
    return r.status;
  }, [method, url, body ? Buffer.from(body).toString('base64') : null, tok]);
  const sDl = await scoped('GET', `/api/services/${svc}/containers/${cid}/files?path=/etc/hostname&format=raw`);
  const sUp = await scoped('PUT', `/api/services/${svc}/volumes/${vol}/files?path=/nope.txt&format=raw`, 'x');
  ctx.check('ops=read: container download allowed', sDl === 200, `status=${sDl}`);
  ctx.check('ops=read: volume upload denied', sDl !== sUp || sUp >= 400, `up status=${sUp}`);

  // --- UI: Files tab shows the container/volume card ----------------------
  await h.goto(`/service/${svc}`);
  await h.tab('Files');
  const ui = await page.evaluate(() => {
    const d = window.__deep('ddm-cfiles');
    if (!d || !d.shadowRoot) return { card: false };
    const t = d.shadowRoot.textContent;
    return {
      card: t.includes('Container / volume files'),
      containerBtn: t.includes('container'),
      volumeBtn: t.includes('volume'),
    };
  });
  ctx.check('ui: cfiles card present', ui.card === true);
  ctx.check('ui: container+volume source buttons', ui.containerBtn && ui.volumeBtn);
}
