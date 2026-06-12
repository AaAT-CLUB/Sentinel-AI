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

function createReflector(isPublic) {
  return {
    getAllAndOverride(key, targets) {
      assert.equal(key, 'isPublic');
      assert.equal(targets.length, 2);
      return isPublic;
    },
  };
}

const previousApiKey = process.env.API_KEY;

try {
  delete process.env.API_KEY;
  const publicGuard = new ApiKeyGuard(createReflector(true));
  assert.equal(publicGuard.canActivate(createContext()), true);

  process.env.API_KEY = 'expected-key';
  const privateGuard = new ApiKeyGuard(createReflector(false));
  assert.throws(
    () => privateGuard.canActivate(createContext({ 'x-api-key': 'wrong-key' })),
    UnauthorizedException,
  );
  assert.equal(privateGuard.canActivate(createContext({ 'x-api-key': 'expected-key' })), true);
} finally {
  if (previousApiKey === undefined) {
    delete process.env.API_KEY;
  } else {
    process.env.API_KEY = previousApiKey;
  }
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

console.log('Auth and throttling guards are global with Public endpoint support.');
