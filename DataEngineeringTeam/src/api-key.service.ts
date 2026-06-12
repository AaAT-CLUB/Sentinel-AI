import { Inject, Injectable } from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { Pool } from 'pg';

export type ApiKeyPrincipal = {
  prefix: string;
  owner: string;
  scopes: string[];
};

type ApiKeyRow = {
  prefix: string;
  key_hash: string;
  owner: string;
  scopes: string[] | string;
  expires_at: Date | string | null;
  revoked_at: Date | string | null;
};

export function extractApiKeyPrefix(rawKey: string): string | undefined {
  const match = rawKey.match(/^sk_sentinel_([A-Za-z0-9]+)_/);
  return match?.[1];
}

export function hashApiKey(rawKey: string, pepper = process.env.API_KEY_PEPPER): string {
  if (!pepper) {
    throw new Error('API_KEY_PEPPER is not configured on this server');
  }
  return createHmac('sha256', pepper).update(rawKey).digest('hex');
}

@Injectable()
export class ApiKeyService {
  constructor(@Inject('PG_POOL') private readonly pool: Pool) {}

  async validate(rawKey: string): Promise<ApiKeyPrincipal | null> {
    const prefix = extractApiKeyPrefix(rawKey);
    if (!prefix) {
      return null;
    }

    const result = await this.pool.query<ApiKeyRow>(
      `SELECT prefix, key_hash, owner, scopes, expires_at, revoked_at
       FROM api_keys
       WHERE prefix = $1
       LIMIT 1`,
      [prefix],
    );
    const key = result.rows[0];
    if (!key || key.revoked_at || this.isExpired(key.expires_at)) {
      return null;
    }

    if (!this.hashesMatch(hashApiKey(rawKey), key.key_hash)) {
      return null;
    }

    await this.pool.query('UPDATE api_keys SET last_used_at = NOW() WHERE prefix = $1', [prefix]);

    return {
      prefix: key.prefix,
      owner: key.owner,
      scopes: this.normalizeScopes(key.scopes),
    };
  }

  private isExpired(expiresAt: Date | string | null): boolean {
    return expiresAt !== null && new Date(expiresAt).getTime() <= Date.now();
  }

  private hashesMatch(actual: string, expected: string): boolean {
    const actualBuffer = Buffer.from(actual, 'hex');
    const expectedBuffer = Buffer.from(expected, 'hex');
    return actualBuffer.length === expectedBuffer.length && timingSafeEqual(actualBuffer, expectedBuffer);
  }

  private normalizeScopes(scopes: string[] | string): string[] {
    if (Array.isArray(scopes)) {
      return scopes;
    }
    return scopes
      .replace(/[{}]/g, '')
      .split(',')
      .map((scope) => scope.trim())
      .filter(Boolean);
  }
}
