const assert = require('node:assert/strict');
const { ForbiddenException, UnauthorizedException } = require('@nestjs/common');
const { of } = require('rxjs');

const { AllExceptionsFilter } = require('../dist/all-exceptions.filter');
const { ApiKeyGuard } = require('../dist/auth.guard');
const { LoggingInterceptor } = require('../dist/logging.interceptor');
const { REQUIRED_SCOPES_KEY } = require('../dist/scopes.decorator');

function createHttpContext(request, response = { statusCode: 200 }) {
  return {
    switchToHttp() {
      return {
        getRequest() {
          return request;
        },
        getResponse() {
          return response;
        },
      };
    },
  };
}

function createGuardContext(request) {
  return {
    getHandler() {
      return createGuardContext;
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

function createLogsService() {
  const entries = [];
  return {
    entries,
    push(entry) {
      entries.push(entry);
    },
  };
}

async function runInterceptor(interceptor, context) {
  await new Promise((resolve, reject) => {
    interceptor.intercept(context, { handle: () => of({ ok: true }) }).subscribe({
      complete: resolve,
      error: reject,
    });
  });
}

async function run() {
  const successLogs = createLogsService();
  const interceptor = new LoggingInterceptor(successLogs);
  await runInterceptor(
    interceptor,
    createHttpContext(
      {
        method: 'GET',
        url: '/vulnerabilities',
        ip: '127.0.0.1',
        headers: {},
        apiKey: { prefix: 'readabcd', owner: 'data-team', scopes: ['read:vulnerabilities'] },
      },
      { statusCode: 200 },
    ),
  );
  assert.equal(successLogs.entries[0].apiKeyPrefix, 'readabcd');

  const rejectedLogs = createLogsService();
  const response = {
    status(statusCode) {
      this.statusCode = statusCode;
      return this;
    },
    send(body) {
      this.body = body;
      return this;
    },
  };
  new AllExceptionsFilter(rejectedLogs).catch(
    new UnauthorizedException('Invalid or missing x-api-key header'),
    createHttpContext({ method: 'GET', url: '/vulnerabilities', ip: '127.0.0.1', headers: {} }, response),
  );
  assert.equal(rejectedLogs.entries[0].apiKeyPrefix, 'NONE');

  const underScopedRequest = { headers: { 'x-api-key': 'sk_sentinel_readabcd_secret' } };
  const guard = new ApiKeyGuard(createReflector({ scopes: ['write:vulnerabilities'] }), {
    async validate() {
      return { prefix: 'readabcd', owner: 'data-team', scopes: ['read:vulnerabilities'] };
    },
  });
  await assert.rejects(
    () => guard.canActivate(createGuardContext(underScopedRequest)),
    ForbiddenException,
  );
  assert.equal(underScopedRequest.apiKey.prefix, 'readabcd');

  console.log('Request logs include API key prefixes and NONE for missing keys.');
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
