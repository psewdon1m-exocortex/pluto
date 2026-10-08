import { constants, createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const version = process.env.PLUTO_VERSION ?? '0.1.0';
const repository = process.env.PLUTO_REPOSITORY;
const keyPath = process.env.PLUTO_RELEASE_KEY_FILE;
let sourceRevision;
try { sourceRevision = execFileSync('git', ['rev-parse', 'HEAD'], {cwd:root,encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim(); }
catch { if (process.env.PLUTO_ALLOW_UNVERSIONED_TEST_BUILD !== '1') throw new Error('A release requires a Git checkout; unversioned fixtures need PLUTO_ALLOW_UNVERSIONED_TEST_BUILD=1.'); }
const toolchain=execFileSync(process.env.GO_BINARY ?? 'go',['env','GOVERSION'],{cwd:root,encoding:'utf8'}).trim();
if(toolchain!=='go1.26.8') throw new Error('Use the qualified Go 1.26.8 toolchain.');
if (!/^\d+\.\d+\.\d+$/.test(version) || !/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(repository ?? '') || !keyPath) {
  throw new Error('Set PLUTO_VERSION, PLUTO_REPOSITORY and PLUTO_RELEASE_KEY_FILE (RSA PEM).');
}
const key = createPrivateKey(readFileSync(keyPath));
if (key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails.modulusLength < 3072) throw new Error('Use an RSA key of at least 3072 bits.');
const publicKey = createPublicKey(key).export({ type: 'spki', format: 'pem' });
const publicKeyBase64 = Buffer.from(publicKey).toString('base64');
const out = process.env.PLUTO_OUTPUT_DIRECTORY ? path.resolve(process.env.PLUTO_OUTPUT_DIRECTORY) : path.join(root, 'dist');
mkdirSync(out, { recursive: true });
const artifacts = {};
for (const arch of ['amd64', 'arm64']) {
  const name = `pluto-linux-${arch}`;
  execFileSync(process.env.GO_BINARY ?? 'go', ['build', '-trimpath', '-ldflags', `-s -w -X main.Version=${version} -X main.ReleasePublicKey=${publicKeyBase64}`, '-o', path.join(out, name), './cmd/pluto'], {
    cwd: root, stdio: 'inherit', env: { ...process.env, GOOS: 'linux', GOARCH: arch, CGO_ENABLED: '0' },
  });
  const bytes = readFileSync(path.join(out, name));
  artifacts[`linux-${arch}`] = { url: `${repository}/releases/download/pluto-v${version}/${name}`, sha256: createHash('sha256').update(bytes).digest('hex'), size: bytes.length };
}
const manifest = Buffer.from(JSON.stringify({ schema: 1, version, sourceRevision:sourceRevision??null, toolchain, artifacts }, null, 2) + '\n');
writeFileSync(path.join(out, 'pluto-release.json'), manifest);
const keyId = createHash('sha256').update(createPublicKey(key).export({type:'spki',format:'der'})).digest('hex');
writeFileSync(path.join(out, 'pluto-release.json.sig.json'), JSON.stringify({schema:'exocortex.release-signature.v1',algorithm:'RSA-PSS-SHA256',key_id:keyId,signature:sign('sha256', manifest, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString('base64')}) + '\n');
writeFileSync(path.join(out, 'release-public.pem'), publicKey);
const unit = readFileSync(path.join(root, 'packaging/pluto.service'), 'utf8').trim();
const bootstrap = readFileSync(path.join(root, 'packaging/bootstrap.sh'), 'utf8')
  .replaceAll('@REPOSITORY@', repository).replaceAll('@VERSION@', version)
  .replaceAll('@PUBLIC_KEY@', publicKeyBase64).replace('@SYSTEMD_UNIT@', unit);
writeFileSync(path.join(out, 'bootstrap.sh'), bootstrap, { mode: 0o755 });
console.log(`Prepared signed Pluto ${version} for Linux amd64 and arm64 in ${out}.`);
