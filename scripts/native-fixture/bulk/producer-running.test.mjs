import assert from 'node:assert/strict';
import test from 'node:test';
import {assertOnlyRunningContainerIds} from './producer.mjs';

const first='a'.repeat(64),second='b'.repeat(64);
test('an idle Docker engine admits an empty expected actor set',()=>{
  for(const output of ['', '\n', '\r\n'])assert.doesNotThrow(()=>assertOnlyRunningContainerIds(output,[]));
});
test('the complete observed actor set must match regardless of order or line endings',()=>{
  assert.doesNotThrow(()=>assertOnlyRunningContainerIds(second+'\r\n'+first+'\r\n',[first,second]));
});
test('an additional unowned running actor closes admission',()=>{
  assert.throws(()=>assertOnlyRunningContainerIds(first+'\n'+second+'\n',[first]));
});
test('a missing expected actor closes admission',()=>{
  assert.throws(()=>assertOnlyRunningContainerIds('',[first]));
});
test('partial IDs and diagnostic text cannot masquerade as actor identities',()=>{
  for(const output of ['abc', 'docker: permission denied', 'A'.repeat(64)])assert.throws(()=>assertOnlyRunningContainerIds(output,[output]));
});
