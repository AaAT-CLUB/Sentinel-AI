import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { Pool } from 'pg';

export interface LogEntry {
  timestamp: string;
  method: string;
  url: string;
  statusCode: number;
  durationMs: number;
  ip: string;
  apiKeyPrefix: string;
  userAgent?: string | null;
}

type LogQuery = {
  limit?: string | number;
  status_code?: string;
  statusCode?: string;
  api_key_prefix?: string;
  apiKeyPrefix?: string;
  method?: string;
  from?: string;
  to?: string;
};

type LogRow = {
  timestamp: Date | string;
  method: string;
  url: string;
  status_code: number;
  duration_ms: number;
  ip: string;
  api_key_prefix: string;
  user_agent: string | null;
};

@Injectable()
export class LogsService {
  constructor(@Inject('PG_POOL') private readonly pool: Pool) {}

  async push(entry: LogEntry) {
    try {
      await this.pool.query(
        `INSERT INTO api_request_logs
         (timestamp, method, url, status_code, duration_ms, ip, api_key_prefix, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
          entry.timestamp,
          entry.method,
          entry.url,
          entry.statusCode,
          entry.durationMs,
          entry.ip,
          entry.apiKeyPrefix,
          entry.userAgent ?? null,
        ],
      );
    } catch {
      // Logging must never break the request path.
    }
  }

  async getAll(query: LogQuery = {}): Promise<LogEntry[]> {
    const params: unknown[] = [];
    const filters: string[] = [];

    const statusCode = this.cleanOptionalString(query.status_code ?? query.statusCode);
    if (statusCode) {
      const parsed = Number(statusCode);
      if (!Number.isInteger(parsed) || parsed < 100 || parsed > 599) {
        throw new BadRequestException('status_code must be an integer between 100 and 599');
      }
      params.push(parsed);
      filters.push(`status_code = $${params.length}`);
    }

    const apiKeyPrefix = this.cleanOptionalString(query.api_key_prefix ?? query.apiKeyPrefix);
    if (apiKeyPrefix) {
      params.push(apiKeyPrefix);
      filters.push(`api_key_prefix = $${params.length}`);
    }

    const method = this.cleanOptionalString(query.method);
    if (method) {
      params.push(method.toUpperCase());
      filters.push(`method = $${params.length}`);
    }

    const from = this.cleanOptionalString(query.from);
    if (from) {
      this.assertValidDate(from, 'from');
      params.push(from);
      filters.push(`timestamp >= $${params.length}`);
    }

    const to = this.cleanOptionalString(query.to);
    if (to) {
      this.assertValidDate(to, 'to');
      params.push(to);
      filters.push(`timestamp <= $${params.length}`);
    }

    const limit = this.parseLimit(query.limit);
    params.push(limit);

    const whereClause = filters.length > 0 ? `WHERE ${filters.join(' AND ')}` : '';
    const result = await this.pool.query<LogRow>(
      `SELECT timestamp, method, url, status_code, duration_ms, ip, api_key_prefix, user_agent
       FROM api_request_logs
       ${whereClause}
       ORDER BY timestamp DESC
       LIMIT $${params.length}`,
      params,
    );

    return result.rows.map((row) => ({
      timestamp: row.timestamp instanceof Date ? row.timestamp.toISOString() : row.timestamp,
      method: row.method,
      url: row.url,
      statusCode: row.status_code,
      durationMs: row.duration_ms,
      ip: row.ip,
      apiKeyPrefix: row.api_key_prefix,
      userAgent: row.user_agent,
    }));
  }

  private parseLimit(value: string | number | undefined): number {
    if (value === undefined || value === '') {
      return 100;
    }

    const limit = Number(value);
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000) {
      throw new BadRequestException('limit must be an integer between 1 and 1000');
    }
    return limit;
  }

  private cleanOptionalString(value: unknown): string | undefined {
    if (typeof value !== 'string' && typeof value !== 'number') {
      return undefined;
    }

    const text = String(value).trim();
    return text.length > 0 ? text : undefined;
  }

  private assertValidDate(value: string, fieldName: string) {
    if (Number.isNaN(Date.parse(value))) {
      throw new BadRequestException(`${fieldName} must be a valid date`);
    }
  }
}
