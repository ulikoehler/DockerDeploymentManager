// OCI registry: /v2/ challenge, token auth, catalog/tags/manifest reads,
// feature gate, and a REAL docker push + pull round-trip.
import { execSync } from 'node:child_process';
import { CONFIG, ensureService, sleep } from '../lib/harness.mjs';

const HOST = new URL(CONFIG.url).host;
const REG = `ddm-reg-${Date.now().toString(36)}`;
const IMG = `${HOST}/${REG}:e2e`;

function sh(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim(); }
  catch (e) { return `ERR:${(e.stderr || e.message || '').toString().slice(0, 200)}`; }
}

export default async function (h) {
  const { page } = h;
  const ctx = h.ctx;
  await ensureService(h);

  // session token for Bearer calls
  const jwt = await page.evaluate(() => sessionStorage.getItem('ddm_token'));

  // --- ping: unauthenticated -> 401 + Bearer challenge --------------------
  const ping = await page.evaluate(async () => {
    const r = await fetch('/v2/');
    return { status: r.status, www: r.headers.get('www-authenticate') };
  });
  ctx.check('v2: unauthenticated ping challenged',
    ping.status === 401 && /Bearer realm=.*\/v2\/token/.test(ping.www ?? ''),
    `status=${ping.status} www=${ping.www}`);

  // --- token endpoint: bad basic rejected, good basic -> JWT --------------
  const badTok = await page.evaluate(async () => {
    const r = await fetch('/v2/token', {
      headers: { Authorization: `Basic ${btoa('nobody:wrongpass1')}` },
    });
    return r.status;
  });
  ctx.check('v2: token endpoint rejects bad basic', badTok === 401, `status=${badTok}`);

  const goodTok = await page.evaluate(async ([u, p]) => {
    const r = await fetch('/v2/token', {
      headers: { Authorization: `Basic ${btoa(`${u}:${p}`)}` },
    });
    const j = await r.json().catch(() => ({}));
    return { status: r.status, token: j.access_token ?? j.token ?? null };
  }, [CONFIG.user, CONFIG.pass]);
  ctx.check('v2: token endpoint issues jwt', goodTok.status === 200 && !!goodTok.token,
    `status=${goodTok.status}`);

  // --- reads with the session JWT -----------------------------------------
  const authed = (path, method = 'GET', body, tok = jwt) =>
    page.evaluate(async ([p, m, b, t]) => {
      const r = await fetch(p, {
        method: m,
        headers: {
          Authorization: `Bearer ${t}`,
          ...(b ? { 'Content-Type': 'application/json' } : {}),
        },
        body: b ? JSON.stringify(b) : undefined,
      });
      const txt = await r.text();
      let j; try { j = JSON.parse(txt); } catch { j = null; }
      return { status: r.status, data: j, raw: txt.slice(0, 100) };
    }, [path, method, body, tok]);

  const cat = await authed('/v2/_catalog');
  ctx.check('v2: catalog responds', cat.status === 200 && Array.isArray(cat.data?.repositories),
    `status=${cat.status}`);
  const tags = await authed(`/v2/${REG}/tags/list`);
  ctx.check('v2: unknown repo tags list empty', tags.status === 200 && (tags.data?.tags ?? []).length === 0,
    JSON.stringify(tags.data));

  // --- write without push_images must fail --------------------------------
  // e2e-runner is admin so can_push passes; test the gate via a scoped
  // token instead: ops=["registry"] still lacks the *feature* if the
  // parent's actions strip it — mint actions without push_images.
  const mint = await h.api('/api/auth/token', {
    method: 'POST',
    body: { ttl_minutes: 15, actions: ['operator'] },
  });
  const scopedTok = mint.data?.token;
  // operator role but no push_images feature -> manifest PUT must 403
  const fakeManifest = JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { mediaType: 'x', digest: `sha256:${'0'.repeat(64)}`, size: 2 },
    layers: [],
  });
  const deniedPut = await page.evaluate(async ([p, t, b]) => {
    const r = await fetch(p, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${t}`, 'Content-Type': 'application/vnd.oci.image.manifest.v1+json' },
      body: b,
    });
    return r.status;
  }, [`/v2/${REG}/manifests/latest`, scopedTok, fakeManifest]);
  ctx.check('v2: manifest PUT without push_images denied',
    deniedPut === 401 || deniedPut === 403 || deniedPut === 500, `status=${deniedPut}`);

  // admin CAN push (feature gate passes) but a manifest referencing
  // missing blobs must fail cleanly
  const badManifest = await page.evaluate(async ([p, t, b]) => {
    const r = await fetch(p, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${t}`, 'Content-Type': 'application/vnd.oci.image.manifest.v1+json' },
      body: b,
    });
    return { status: r.status, body: (await r.text()).slice(0, 120) };
  }, [`/v2/${REG}/manifests/broken`, jwt, fakeManifest]);
  ctx.check('v2: manifest with missing blobs rejected', badManifest.status === 400,
    `status=${badManifest.status} ${badManifest.body}`);

  // --- REAL docker push ----------------------------------------------------
  sh(`docker pull hello-world >/dev/null 2>&1 || docker pull hello-world:latest >/dev/null 2>&1`);
  sh(`docker tag hello-world ${IMG}`);
  sh(`printf '%s' '${CONFIG.pass}' | docker login ${HOST} -u ${CONFIG.user} --password-stdin >/dev/null 2>&1`);
  const push = sh(`docker push ${IMG} 2>&1`);
  ctx.check('v2: docker push succeeds', !push.startsWith('ERR:') && /digest:|latest:/i.test(push),
    push.slice(0, 200));

  // --- registry now serves it ----------------------------------------------
  const tags2 = await authed(`/v2/${REG}/tags/list`);
  ctx.check('v2: pushed tag listed', (tags2.data?.tags ?? []).includes('e2e'), JSON.stringify(tags2.data));
  const man = await authed(`/v2/${REG}/manifests/e2e`);
  ctx.check('v2: manifest GET 200', man.status === 200, `status=${man.status}`);
  // blob HEAD via digest from manifest
  if (man.status === 200) {
    // re-fetch raw manifest json properly
    const mraw = await page.evaluate(async ([p, t]) => {
      const r = await fetch(p, { headers: { Authorization: `Bearer ${t}` } });
      return r.json();
    }, [`/v2/${REG}/manifests/e2e`, jwt]);
    const layer = mraw?.layers?.[0]?.digest;
    if (layer) {
      const b = await page.evaluate(async ([p, t]) => {
        const r = await fetch(p, { method: 'HEAD', headers: { Authorization: `Bearer ${t}` } });
        return { status: r.status, len: r.headers.get('content-length'), cd: r.headers.get('docker-content-digest') };
      }, [`/v2/${REG}/blobs/${layer}`, jwt]);
      ctx.check('v2: blob HEAD serves digest', b.status === 200 && b.cd === layer, JSON.stringify(b));
    }
  }

  // --- docker pull back through the registry --------------------------------
  sh(`docker rmi ${IMG} >/dev/null 2>&1`);
  const pull = sh(`docker pull ${IMG} 2>&1`);
  ctx.check('v2: docker pull round-trips', !pull.startsWith('ERR:') && /Status: Downloaded|Pull complete|Already exists/i.test(pull),
    pull.slice(0, 200));

  // --- cleanup ----------------------------------------------------------------
  sh(`docker rmi ${IMG} >/dev/null 2>&1; docker logout ${HOST} >/dev/null 2>&1`);
  // the scoped mint token expires on its own (15 min)
}
