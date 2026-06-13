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
    user_agent: 'curl/8.5.0',
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
    'curl/8.5.0',
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
    user_agent: null,
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
      user_agent: 'curl/8.5.0',
    },
  ]);

  const camelAliasPool = createPool();
  await new LogsService(camelAliasPool).getAll({
    statusCode: '403',
    apiKeyPrefix: 'readabcd',
    limit: '5',
  });
  assert.equal(camelAliasPool.calls[0].params.length, 1);
  assert.deepEqual(camelAliasPool.calls[0].params, [5]);
  assert.doesNotMatch(camelAliasPool.calls[0].sql, /status_code =/);
  assert.doesNotMatch(camelAliasPool.calls[0].sql, /api_key_prefix =/);

  await assert.rejects(
    () => new LogsService(createPool()).getAll({ limit: '1001' }),
    /limit must be an integer between 1 and 1000/,
  );

  const schemaPool = createPool((sql) => {
    if (/information_schema\.columns/.test(sql)) {
      return {
        rows: [
          { column_name: 'id' },
          { column_name: 'timestamp' },
          { column_name: 'method' },
          { column_name: 'url' },
          { column_name: 'status_code' },
          { column_name: 'duration_ms' },
          { column_name: 'ip' },
          { column_name: 'api_key_prefix' },
          { column_name: 'user_agent' },
          { column_name: 'created_at' },
        ],
      };
    }
    if (/pg_indexes/.test(sql)) {
      return {
        rows: [
          { indexname: 'api_request_logs_pkey' },
          { indexname: 'idx_api_request_logs_timestamp_desc' },
          { indexname: 'idx_api_request_logs_api_key_prefix_timestamp' },
          { indexname: 'idx_api_request_logs_status_code_timestamp' },
          { indexname: 'idx_api_request_logs_method_timestamp' },
        ],
      };
    }
    return { rows: [], rowCount: 0 };
  });
  await new LogsService(schemaPool).onModuleInit();

  const missingSchemaPool = createPool((sql) => {
    if (/information_schema\.columns/.test(sql)) {
      return { rows: [{ column_name: 'timestamp' }] };
    }
    return { rows: [] };
  });
  await assert.rejects(
    () => new LogsService(missingSchemaPool).onModuleInit(),
    /api_request_logs schema is missing required columns/,
  );

  console.log('Request logs persist to PostgreSQL and query durable rows.');
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
