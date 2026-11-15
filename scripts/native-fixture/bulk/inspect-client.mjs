import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';

const cid = process.env.QUALITY_PG_ID;
const nonce = process.env.QUALITY_INSPECT_NONCE;
assert.match(cid, /^[a-f0-9]{64}$/);
assert.match(nonce, /^[a-f0-9]{64}$/);
const requested = process.argv[3];
assert.deepEqual(process.argv.slice(2), ['inspect', requested]);
const sftp = process.env.QUALITY_SFTP_ID;
assert.match(sftp, /^[a-f0-9]{64}$/);
if (requested === sftp) {
  const stored = JSON.parse(await fs.readFile('/input/sftp.inspect.json', 'utf8'));
  assert.equal(stored.nonce, nonce);
  assert.equal(stored.data.length, 1);
  assert.equal(stored.data[0].Id, sftp);
  process.stdout.write(JSON.stringify(stored.data));
  process.exit(0);
}
assert.equal(requested, cid);
const request = '/inspection/request';
await fs.writeFile(request + '.tmp', JSON.stringify({ nonce, cid }), { flag: 'wx', mode: 0o600 });
await fs.rename(request + '.tmp', request + '.json');
const deadline = Date.now() + 20000;
while (Date.now() < deadline) {
  try {
    const response = JSON.parse(await fs.readFile('/inspection/response.json', 'utf8'));
    assert.equal(response.nonce, nonce);
    assert.equal(response.data.length, 1);
    assert.equal(response.data[0].Id, cid);
    process.stdout.write(JSON.stringify(response.data));
    process.exitCode = 0;
    break;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    await delay(50);
  }
}
if (process.exitCode !== 0) throw new Error('Qualified Docker inspect relay expired');
