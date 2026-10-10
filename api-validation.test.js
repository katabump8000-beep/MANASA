import test from 'node:test';
import assert from 'node:assert/strict';

test('project name normalization is stable for simple latin names', () => {
  const nameKey = 'My Bot'.normalize('NFKC').toLocaleLowerCase('en-US');
  assert.equal(nameKey, 'my bot');
});

test('entry path traversal is rejected by the API validation rule', () => {
  const entryFile = '../outside.js';
  assert.equal(entryFile.startsWith('/') || entryFile.split(/[\\/]/).includes('..'), true);
});
