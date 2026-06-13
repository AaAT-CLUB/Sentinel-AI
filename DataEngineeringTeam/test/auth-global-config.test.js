const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { UnauthorizedException } = require('@nestjs/common');
const { ApiKeyGuard } = require('../dist/auth.guard');

function createContext(headers = {}) {
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
          return { headers };
        },
      };
    },
  };
}

function createReflector(isPublic, scopes = []) {
  return {
    getAllAndOverride(key, targets) {
      assert.equal(targets.length, 2);
      if (key === 'isPublic') {
        return isPublic;
      }
      if (key === 'requiredScopes') {
        return scopes;
      }
      assert.fail(`unexpected metadata key ${key}`);
      return isPublic;
    },
  };
}

async function runGuardChecks() {
  const publicGuard = new ApiKeyGuard(createReflector(true), {
    async validate() {
      throw new Error('public routes must not validate API keys');
    },
  });
  assert.equal(await publicGuard.canActivate(createContext()), true);

  const privateGuard = new ApiKeyGuard(createReflector(false), {
    async validate() {
      return null;
    },
  });
  await assert.rejects(
    () => privateGuard.canActivate(createContext({ 'x-api-key': 'wrong-key' })),
    UnauthorizedException,
  );
}

const appModuleSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'app.module.ts'), 'utf8');
assert.match(appModuleSource, /provide:\s*APP_GUARD,\s*useClass:\s*ApiKeyGuard/s);
assert.match(appModuleSource, /provide:\s*APP_GUARD,\s*useClass:\s*ThrottlerGuard/s);
assert(
  appModuleSource.indexOf('useClass: ThrottlerGuard') <
    appModuleSource.indexOf('useClass: ApiKeyGuard'),
  'ThrottlerGuard should run before ApiKeyGuard so unauthenticated spam is rate-limited',
);

const controllerSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'app.controller.ts'), 'utf8');
assert.match(controllerSource, /@Public\(\)\s*\r?\n\s*@Get\('health'\)/);
assert.doesNotMatch(controllerSource, /UseGuards/);
assert.doesNotMatch(fs.readFileSync(path.join(__dirname, '..', 'src', 'auth.guard.ts'), 'utf8'), /process\.env\.API_KEY/);

runGuardChecks()
  .then(() => {
    console.log('Auth and throttling guards are global with Public endpoint support.');
  })
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
