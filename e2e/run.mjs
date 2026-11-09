// DDM E2E suite runner.
// Env: DDM_URL, DDM_USER, DDM_PASS, CHROME_PATH, E2E_SVC, E2E_GIT_URL,
//      E2E_ONLY (comma-separated test file prefixes to run, e.g. "10,20")
import { launch, deleteService, CONFIG } from './lib/harness.mjs';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const testsDir = path.join(dir, 'tests');
const only = process.env.E2E_ONLY ? process.env.E2E_ONLY.split(',') : null;

const files = fs.readdirSync(testsDir).filter(f => f.endsWith('.mjs')).sort()
  .filter(f => !only || only.some(p => f.startsWith(p)));

if (!CONFIG.pass) {
  console.error('DDM_PASS is required (password for DDM_USER)');
  process.exit(2);
}

const { ctx, h } = await launch();
console.log(`DDM E2E — ${CONFIG.url} as ${CONFIG.user}, scratch service '${CONFIG.svc}'`);
console.log(`Chrome: ${process.env.CHROME_PATH || '/usr/bin/google-chrome'}`);
console.log('-'.repeat(60));

let crashed = null;
try {
  await h.login();
  for (const f of files) {
    const mod = await import(path.join(testsDir, f));
    console.log(`\n== ${f} ==`);
    try {
      await mod.default(h);
    } catch (e) {
      crashed = `${f}: ${e.message}`;
      ctx.fail(`${f}: module crashed`, String(e).slice(0, 200));
      console.log('  [crash]', String(e).slice(0, 300));
    }
  }
} catch (e) {
  crashed = `setup: ${e.message}`;
  console.error('SETUP FAILED:', e.message);
}

// cleanup scratch service
console.log('\n== cleanup ==');
try { await deleteService(h, CONFIG.svc); console.log('  scratch service removed'); }
catch (e) { console.log('  cleanup warning:', e.message); }

await h.browser.close();

const fails = ctx.results.filter(r => !r.ok);
console.log('\n' + '='.repeat(60));
console.log(`RESULT: ${ctx.results.length - fails.length}/${ctx.results.length} passed`);
if (fails.length) {
  console.log('FAILURES:');
  fails.forEach(f => console.log('  -', f.name, f.detail ? `(${f.detail.slice(0, 120)})` : ''));
}
process.exit(fails.length || crashed ? 1 : 0);
