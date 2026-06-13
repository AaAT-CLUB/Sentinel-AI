const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const mainSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'main.ts'), 'utf8');

assert.match(mainSource, /const port = Number\(process\.env\.PORT\) \|\| 3000;/);
assert.match(mainSource, /const host = process\.env\.HOST \|\| '127\.0\.0\.1';/);
assert.match(mainSource, /await app\.listen\(port, host\);/);
assert.doesNotMatch(mainSource, /app\.listen\(3000,\s*'0\.0\.0\.0'\)/);

console.log('Data API listen config defaults to loopback and keeps env overrides.');
