const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ForbiddenException, UnauthorizedException } = require('@nestjs/common');

const { ApiKeyGuard } = require('../dist/auth.guard');
const { ApiKeyService, hashApiKey } = require('../dist/api-key.service');
const { REQUIRED_SCOPES_KEY } = require('../dist/scopes.decorator');

function createPool(rows, updateCalls = []) {
  return {
    async query(sql, params) {
      if (/UPDATE api_keys/i.test(sql)) {
        updateCalls.push({ sql, params });
        return { rows: [], rowCount: 1 };
      }
      return { rows, rowCount: rows.length };
    },
  };
}

function createReflector({ isPublic = false, scopes = [] } = {}) {
  return {
    getAllAndOverride(key) {
      if (key === 'isPublic') {
        return isPublic;
      }
      if (key === REQUIRED_SCOPES_KEY) {
        return scopes;
      }
      return undefined;
    },
  };
}

function createContext(headers = {}) {
  const request = { headers };
  return {
    getHandler() {
      return createContext;
    },
    getClass() {
      return ApiKeyGuard;
    },
    switchToHttp() {
      return {
        getRequest() {
          return request;
        },
      };
    },
  };
}

async function assertRejectsWith(fn, errorClass) {
  await assert.rejects(fn, (error) => error instanceof errorClass);
}

async function run() {
  const previousPepper = process.env.API_KEY_PEPPER;
  const rawKey = 'sk_sentinel_readabcd_secretpart';

  try {
    process.env.API_KEY_PEPPER = 'test-pepper';

    assert.equal(hashApiKey(rawKey), hashApiKey(rawKey));
    assert.notEqual(hashApiKey(rawKey), hashApiKey(`${rawKey}x`));

    const updateCalls = [];
    const validRow = {
      prefix: 'readabcd',
      key_hash: hashApiKey(rawKey),
      owner: 'data-team',
      scopes: ['read:vulnerabilities'],
      expires_at: null,
      revoked_at: null,
    };

    const service = new ApiKeyService(createPool([validRow], updateCalls));
    const guard = new ApiKeyGuard(
      createReflector({ scopes: ['read:vulnerabilities'] }),
      service,
    );

    const accepted = await guard.canActivate(createContext({ 'x-api-key': rawKey }));
    assert.equal(accepted, true);
    assert.equal(updateCalls.length, 1);

    await assertRejectsWith(
      () => guard.canActivate(createContext({ 'x-api-key': `${rawKey}x` })),
      UnauthorizedException,
    );

    await assertRejectsWith(
      () =>
        new ApiKeyGuard(
          createReflector({ scopes: ['write:vulnerabilities'] }),
          new ApiKeyService(createPool([validRow])),
        ).canActivate(createContext({ 'x-api-key': rawKey })),
      ForbiddenException,
    );

    await assertRejectsWith(
      () =>
        new ApiKeyGuard(
          createReflector({ scopes: ['read:vulnerabilities'] }),
          new ApiKeyService(createPool([{ ...validRow, revoked_at: new Date().toISOString() }])),
        ).canActivate(createContext({ 'x-api-key': rawKey })),
      UnauthorizedException,
    );

    await assertRejectsWith(
      () =>
        new ApiKeyGuard(
          createReflector({ scopes: ['read:vulnerabilities'] }),
          new ApiKeyService(createPool([{ ...validRow, expires_at: '2000-01-01T00:00:00.000Z' }])),
        ).canActivate(createContext({ 'x-api-key': rawKey })),
      UnauthorizedException,
    );

    const publicGuard = new ApiKeyGuard(createReflector({ isPublic: true }), service);
    assert.equal(await publicGuard.canActivate(createContext()), true);

    const controllerSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'app.controller.ts'), 'utf8');
    assert.match(controllerSource, /@RequireScopes\('read:vulnerabilities'\)/);
    assert.match(controllerSource, /@RequireScopes\('write:vulnerabilities'\)/);
    assert.match(controllerSource, /@RequireScopes\('import:cves'\)/);
    assert.match(controllerSource, /@RequireScopes\('admin:logs'\)/);
  } finally {
    if (previousPepper === undefined) {
      delete process.env.API_KEY_PEPPER;
    } else {
      process.env.API_KEY_PEPPER = previousPepper;
    }
  }

  console.log('Scoped hashed API key guard rejects invalid, revoked, expired, and under-scoped keys.');
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
