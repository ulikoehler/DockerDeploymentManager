// Batch-7 coverage: session user-agent, WS tickets, git range diff,
// api-docs sync.
import { CONFIG, ensureService, sleep } from '../lib/harness.mjs';

export default async function (h) {
  const { page } = h;
  const ctx = h.ctx;
  await ensureService(h);

  // --- sessions record user-agent ---------------------------------------
  const toks = await h.api('/api/auth/tokens');
  const sessions = (toks.data ?? []).filter((t) => t.kind === 'session' && !t.revoked);
  const withUa = sessions.filter((t) => t.ua && t.ua.length > 3);
  ctx.check('sessions: user-agent recorded', withUa.length >= 1,
    `sessions=${sessions.length} withUa=${withUa.length}`);

  await h.goto('/token');
  await sleep(1200);
  const tokTxt = await h.compText('ddm-token');
  ctx.check('tokens: client column renders', /client/.test(tokTxt) && /Chrome/i.test(tokTxt),
    tokTxt.slice(0, 200));

  // --- WS tickets: mint → redeem → stream -------------------------------
  const tk = await h.api('/api/auth/ws-ticket', { method: 'POST' });
  ctx.check('ws: ticket minted', !!tk.data?.ticket, JSON.stringify(tk.data).slice(0, 80));
  if (tk.data?.ticket) {
    // open a real websocket with the ticket from the page
    const wsOk = await page.evaluate(async (ticket, svc) => {
      const url = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/services/${svc}/logs?ticket=${ticket}&tail=5`;
      return await new Promise((resolve) => {
        const ws = new WebSocket(url);
        const to = setTimeout(() => { ws.close(); resolve('timeout'); }, 8000);
        ws.onopen = () => { clearTimeout(to); ws.close(); resolve('open'); };
        ws.onmessage = () => { clearTimeout(to); ws.close(); resolve('message'); };
        ws.onerror = () => { clearTimeout(to); resolve('error'); };
        ws.onclose = (e) => { if (e.code === 1008) resolve('policy-close'); };
      });
    }, tk.data.ticket, CONFIG.svc);
    ctx.check('ws: ticket connects to log stream', ['open', 'message'].includes(wsOk), wsOk);
    // single-use: redeeming the same ticket again must fail
    const reuse = await page.evaluate(async (ticket) => {
      const url = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/events?ticket=${ticket}`;
      return await new Promise((resolve) => {
        const ws = new WebSocket(url);
        const to = setTimeout(() => { ws.close(); resolve('timeout'); }, 6000);
        ws.onopen = () => { clearTimeout(to); ws.close(); resolve('open'); };
        ws.onclose = (e) => { if (e.code !== 1000 || !e.wasClean) resolve('rejected'); };
      });
    }, tk.data.ticket);
    ctx.check('ws: ticket is single-use', wsOk !== 'error' && (reuse === 'rejected' || reuse === 'timeout'), `first=${wsOk} reuse=${reuse}`);
  }

  // --- git diff ?base= ----------------------------------------------------
  const diffDefault = await h.api(`/api/services/${CONFIG.svc}/git/diff`);
  ctx.check('git diff: endpoint responds', [200, 400].includes(diffDefault.status),
    `status=${diffDefault.status}`);
  const diffBase = await h.api(`/api/services/${CONFIG.svc}/git/diff?base=${encodeURIComponent('HEAD~1')}`);
  ctx.check('git diff: base ref accepted (or repo-missing 400)', [200, 400].includes(diffBase.status),
    `status=${diffBase.status}`);
  const diffBad = await h.api(`/api/services/${CONFIG.svc}/git/diff?base=${encodeURIComponent('--upload-pack=x')}`);
  ctx.check('git diff: option injection rejected', diffBad.status === 400,
    `status=${diffBad.status} ${JSON.stringify(diffBad.data).slice(0, 100)}`);

  // --- api docs lists new endpoints ---------------------------------------
  await h.goto('/api');
  await sleep(1200);
  const docsTxt = await h.compText('ddm-api-docs');
  ctx.check('api-docs: cancel endpoint documented', /executions\/:id\/cancel/.test(docsTxt));
  ctx.check('api-docs: meta endpoint documented', /services\/:name\/meta/.test(docsTxt));
  ctx.check('api-docs: diff base documented', /git\/diff/.test(docsTxt) && /base/.test(docsTxt));
}
