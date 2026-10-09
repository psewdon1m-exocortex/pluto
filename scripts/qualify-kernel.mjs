import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const kernelRoot = path.resolve(process.argv[2] ?? '');
const pin = name => readFileSync(path.join(projectRoot, '.release', name), 'utf8').trim();
const expectedSource = pin('kernel.source-sha');
const expectedVersion = pin('kernel.version');

assert.match(expectedSource, /^[a-f0-9]{40}$/);
assert.match(expectedVersion, /^\d+\.\d+\.\d+$/);
assert.equal(execFileSync('git', ['-C', kernelRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(), expectedSource);
assert.equal(JSON.parse(readFileSync(path.join(kernelRoot, 'package.json'), 'utf8')).version, expectedVersion);

const requireFromKernel = createRequire(path.join(kernelRoot, 'package.json'));
const request = requireFromKernel('supertest');
const { createKernelApp } = await import(pathToFileURL(path.join(kernelRoot, 'server', 'app.js')));
const { OUTDOOR_KEYS, PRINCIPALS_SETTING } = await import(pathToFileURL(path.join(kernelRoot, 'server', 'machine-principals.js')));

const directory = mkdtempSync(path.join(os.tmpdir(), 'pluto-kernel-contract-'));
const refs = {
  'services.saturn.sni': 'volt://33333333-3333-4333-8333-333333333331/1',
  'services.saturn.port': 'volt://33333333-3333-4333-8333-333333333332/1',
  'repositories.pluto.url': 'volt://33333333-3333-4333-8333-333333333333/1',
  'repositories.updater.url': 'volt://33333333-3333-4333-8333-333333333334/1',
};
const values = {
  [refs['services.saturn.sni']]: 'saturn.example.org',
  [refs['services.saturn.port']]: '443',
  [refs['repositories.pluto.url']]: 'https://github.com/psewdon1m-exocortex/pluto',
  [refs['repositories.updater.url']]: 'https://github.com/psewdon1m-exocortex/updater',
};
let secret = false;
const app = createKernelApp({
  dataDir: directory,
  defaultsDir: path.join(kernelRoot, 'data', 'defaults'),
  distDir: path.join(directory, 'none'),
  accessKey: 'operator',
  sessionSecret: 's'.repeat(40),
  apiToken: 'legacy-' + 'a'.repeat(32),
  diskPath: directory,
  voltClient: {
    async resolve(references) {
      return {
        schema: 'volt.resolve.v1',
        resolution_revision: 'pluto-qualification',
        values: Object.fromEntries(references.map(reference => [reference, {
          value: values[reference],
          visibility: secret && reference === refs['repositories.pluto.url'] ? 'secret' : 'plain',
          revision: 1,
        }])),
      };
    },
  },
  serviceStatusFetch: async () => { throw new Error('offline qualification fixture'); },
});

try {
  app.locals.kernel.store.upsertRegisterEntries(Object.entries(refs).map(([key, value]) => ({
    key, value, description: `Pluto qualification: ${key}`,
  })), 'pluto-qualification', { replace: true });
  const operator = request.agent(app);
  assert.equal((await operator.post('/api/auth/login').send({ access_key: 'operator' })).status, 200);
  const created = await operator.post('/api/outdoor-tokens').send({ name: 'Pluto release qualification' });
  assert.equal(created.status, 201);
  const { id, token } = created.body;
  assert.equal(typeof token, 'string');
  assert.ok(token.length >= 24);

  const principals = JSON.parse(app.locals.kernel.store.getSetting(PRINCIPALS_SETTING));
  const principal = principals.find(item => item.id === id);
  assert.deepEqual(principal.allowed_keys, OUTDOOR_KEYS);
  assert.deepEqual(OUTDOOR_KEYS, ['services.saturn.sni', 'services.saturn.port', 'repositories.pluto.url']);

  const resolve = (credential, keys) => request(app)
    .post('/api/v1/register/resolve')
    .set('Authorization', `Bearer ${credential}`)
    .send({ keys });
  const keys = [...OUTDOOR_KEYS];
  const discovered = await resolve(token, keys);
  assert.equal(discovered.status, 200, JSON.stringify(discovered.body));
  assert.deepEqual(Object.fromEntries(keys.map(key => [key, discovered.body.values[key].value])), {
    'services.saturn.sni': 'saturn.example.org',
    'services.saturn.port': '443',
    'repositories.pluto.url': 'https://github.com/psewdon1m-exocortex/pluto',
  });
  assert.equal((await resolve(token, ['repositories.updater.url'])).status, 403);

  secret = true;
  assert.equal((await resolve(token, ['repositories.pluto.url'])).status, 403);
  secret = false;
  const rotated = await operator.post(`/api/outdoor-tokens/${id}/rotate`).send({});
  assert.equal(rotated.status, 200);
  assert.equal((await resolve(token, keys)).status, 401);
  assert.equal((await resolve(rotated.body.token, keys)).status, 200);
  assert.equal((await operator.delete(`/api/outdoor-tokens/${id}`)).status, 200);
  assert.equal((await resolve(rotated.body.token, keys)).status, 401);
  console.log(`Qualified Pluto discovery against Kernel ${expectedVersion} (${expectedSource}).`);
} finally {
  app.locals.kernel.close();
  rmSync(directory, { recursive: true, force: true });
}
