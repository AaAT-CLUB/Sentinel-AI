const assert = require('node:assert/strict');
const { LogsService } = require('../dist/logs.service');

function createPool(queryHandler) {
  const calls = [];
  return {
    calls,
    async query(sql, params = []) {
      calls.push({ sql, params });
      return queryHandler?.(sql, params) ?? { rows: [], rowCount: 0 };
    },
  };
}

async function run() {
  const insertPool = createPool();
  const service = new LogsService(insertPool);

  await service.push({
    timestamp: '2026-06-12T20:00:00.000Z',
    method: 'GET',
    url: '/vulnerabilities?limit=1',
    statusCode: 200,
    durationMs: 12,
    ip: '127.0.0.1',
    apiKeyPrefix: 'readabcd',
  });

  assert.match(insertPool.calls[0].sql, /INSERT INTO api_request_logs/);
  assert.deepEqual(insertPool.calls[0].params, [
    '2026-06-12T20:00:00.000Z',
    'GET',
    '/vulnerabilities?limit=1',
    200,
    12,
    '127.0.0.1',
    'readabcd',
    null,
  ]);

  const failingPool = createPool(() => {
    throw new Error('database unavailable');
  });
  await new LogsService(failingPool).push({
    timestamp: '2026-06-12T20:00:00.000Z',
    method: 'GET',
    url: '/health',
    statusCode: 200,
    durationMs: 1,
    ip: '127.0.0.1',
    apiKeyPrefix: 'NONE',
  });

  const selectPool = createPool((sql) => {
    if (/SELECT timestamp, method/.test(sql)) {
      return {
        rows: [
          {
            timestamp: '2026-06-12T20:00:00.000Z',
            method: 'POST',
            url: '/import-cves',
            status_code: 403,
            duration_ms: 0,
            ip: '127.0.0.1',
            api_key_prefix: 'readabcd',
            user_agent: 'curl/8.5.0',
          },
        ],
      };
    }
    return { rows: [], rowCount: 0 };
  });

  const rows = await new LogsService(selectPool).getAll({
    limit: '25',
    status_code: '403',
    api_key_prefix: 'readabcd',
    method: 'POST',
    from: '2026-06-12T00:00:00.000Z',
    to: '2026-06-13T00:00:00.000Z',
  });

  assert.match(selectPool.calls[0].sql, /FROM api_request_logs/);
  assert.match(selectPool.calls[0].sql, /status_code = \$1/);
  assert.match(selectPool.calls[0].sql, /api_key_prefix = \$2/);
  assert.match(selectPool.calls[0].sql, /method = \$3/);
  assert.match(selectPool.calls[0].sql, /timestamp >= \$4/);
  assert.match(selectPool.calls[0].sql, /timestamp <= \$5/);
  assert.match(selectPool.calls[0].sql, /LIMIT \$6/);
  assert.deepEqual(selectPool.calls[0].params, [
    403,
    'readabcd',
    'POST',
    '2026-06-12T00:00:00.000Z',
    '2026-06-13T00:00:00.000Z',
    25,
  ]);
  assert.deepEqual(rows, [
    {
      timestamp: '2026-06-12T20:00:00.000Z',
      method: 'POST',
      url: '/import-cves',
      statusCode: 403,
      durationMs: 0,
      ip: '127.0.0.1',
      apiKeyPrefix: 'readabcd',
      userAgent: 'curl/8.5.0',
    },
  ]);

  await assert.rejects(
    () => new LogsService(createPool()).getAll({ limit: '1001' }),
    /limit must be an integer between 1 and 1000/,
  );

  console.log('Request logs persist to PostgreSQL and query durable rows.');
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
