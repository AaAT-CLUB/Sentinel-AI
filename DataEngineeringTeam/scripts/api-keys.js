const crypto = require('node:crypto');
const { Pool } = require('pg');
require('dotenv').config({ quiet: true });

function hashApiKey(rawKey, pepper = process.env.API_KEY_PEPPER) {
  if (!pepper) {
    throw new Error('API_KEY_PEPPER is not configured');
  }
  return crypto.createHmac('sha256', pepper).update(rawKey).digest('hex');
}

function createPoolFromEnv() {
  return new Pool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
  });
}

function randomToken(bytes = 18) {
  return crypto.randomBytes(bytes).toString('base64url');
}

async function migrateApiKeys(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id SERIAL PRIMARY KEY,
      prefix VARCHAR(32) UNIQUE NOT NULL,
      key_hash TEXT NOT NULL,
      owner TEXT NOT NULL,
      scopes TEXT[] NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMP NULL,
      revoked_at TIMESTAMP NULL,
      last_used_at TIMESTAMP NULL
    )
  `);
}

async function createApiKey(pool, options) {
  if (!options.owner) {
    throw new Error('--owner is required');
  }
  if (!options.scopes || options.scopes.length === 0) {
    throw new Error('--scopes is required');
  }

  const prefix = options.prefix ?? randomToken(6).replace(/[^A-Za-z0-9]/g, '').slice(0, 10);
  const secret = options.secret ?? randomToken(32);
  const rawKey = `sk_sentinel_${prefix}_${secret}`;
  const keyHash = hashApiKey(rawKey);

  const result = await pool.query(
    `INSERT INTO api_keys (prefix, key_hash, owner, scopes, expires_at)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING prefix, owner, scopes, created_at, expires_at`,
    [prefix, keyHash, options.owner, options.scopes, options.expiresAt ?? null],
  );

  return {
    ...result.rows[0],
    key: rawKey,
  };
}

async function listApiKeys(pool) {
  const result = await pool.query(
    `SELECT prefix, owner, scopes, created_at, expires_at, revoked_at, last_used_at
     FROM api_keys
     ORDER BY created_at DESC`,
  );
  return result.rows;
}

async function revokeApiKey(pool, prefix) {
  if (!prefix) {
    throw new Error('--prefix is required');
  }
  await pool.query('UPDATE api_keys SET revoked_at = NOW() WHERE prefix = $1', [prefix]);
}

function parseArgs(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--owner') {
      options.owner = argv[++i];
    } else if (arg === '--scopes') {
      options.scopes = argv[++i]?.split(',').map((scope) => scope.trim()).filter(Boolean);
    } else if (arg === '--expires-at') {
      options.expiresAt = argv[++i];
    } else if (arg === '--prefix') {
      options.prefix = argv[++i];
    }
  }
  return options;
}

async function main() {
  const [command, ...argv] = process.argv.slice(2);
  const pool = createPoolFromEnv();

  try {
    if (command === 'migrate') {
      await migrateApiKeys(pool);
      console.log('api_keys table is ready');
    } else if (command === 'create') {
      const created = await createApiKey(pool, parseArgs(argv));
      console.log(JSON.stringify(created, null, 2));
    } else if (command === 'list') {
      console.log(JSON.stringify(await listApiKeys(pool), null, 2));
    } else if (command === 'revoke') {
      await revokeApiKey(pool, parseArgs(argv).prefix);
      console.log('API key revoked');
    } else {
      throw new Error('Usage: node scripts/api-keys.js <migrate|create|list|revoke>');
    }
  } finally {
    await pool.end();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = {
  createApiKey,
  hashApiKey,
  listApiKeys,
  migrateApiKeys,
  revokeApiKey,
};
