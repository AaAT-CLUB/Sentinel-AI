const assert = require('node:assert/strict');

const {
  createApiKey,
  listApiKeys,
  migrateApiKeys,
  revokeApiKey,
} = require('../scripts/api-keys');

function createPool() {
  const calls = [];
  return {
    calls,
    async query(sql, params = []) {
      calls.push({ sql, params });
      if (/RETURNING prefix, owner, scopes, created_at, expires_at/.test(sql)) {
        return {
          rows: [
            {
              prefix: params[0],
              owner: params[2],
              scopes: params[3],
              created_at: '2026-06-12T00:00:00.000Z',
              expires_at: params[4],
            },
          ],
        };
      }
      if (/SELECT prefix, owner, scopes/.test(sql)) {
        return {
          rows: [
            {
              prefix: 'readabcd',
              owner: 'data-team',
              scopes: ['read:vulnerabilities'],
              created_at: '2026-06-12T00:00:00.000Z',
              expires_at: null,
              revoked_at: null,
              last_used_at: null,
            },
          ],
        };
      }
      return { rows: [], rowCount: 1 };
    },
  };
}

async function run() {
  const previousPepper = process.env.API_KEY_PEPPER;
  try {
    process.env.API_KEY_PEPPER = 'script-test-pepper';

    const migratePool = createPool();
    await migrateApiKeys(migratePool);
    assert.match(migratePool.calls[0].sql, /CREATE TABLE IF NOT EXISTS api_keys/);
    assert.match(migratePool.calls[0].sql, /key_hash TEXT NOT NULL/);
    assert.match(migratePool.calls[0].sql, /scopes TEXT\[\] NOT NULL/);

    const createPoolInstance = createPool();
    const created = await createApiKey(createPoolInstance, {
      owner: 'data-team',
      scopes: ['read:vulnerabilities', 'import:cves'],
      prefix: 'readabcd',
      secret: 'fixedsecret',
    });
    assert.equal(created.key, 'sk_sentinel_readabcd_fixedsecret');
    assert.equal(createPoolInstance.calls[0].params[0], 'readabcd');
    assert.notEqual(createPoolInstance.calls[0].params[1], created.key);
    assert.equal(createPoolInstance.calls[0].params[1].length, 64);

    const rows = await listApiKeys(createPool());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].prefix, 'readabcd');

    const revokePool = createPool();
    await revokeApiKey(revokePool, 'readabcd');
    assert.match(revokePool.calls[0].sql, /UPDATE api_keys/);
    assert.deepEqual(revokePool.calls[0].params, ['readabcd']);
  } finally {
    if (previousPepper === undefined) {
      delete process.env.API_KEY_PEPPER;
    } else {
      process.env.API_KEY_PEPPER = previousPepper;
    }
  }

  console.log('API key scripts migrate, create, list, and revoke scoped hashed keys.');
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
