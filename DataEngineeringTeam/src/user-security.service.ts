import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { Pool } from 'pg';

@Injectable()
export class UserSecurityService {
  constructor(@Inject('PG_POOL') private readonly pool: Pool) {}

  hashUsername(username: string): string {
    const pepper = process.env.APP_USER_PEPPER;

    if (!pepper) {
      throw new Error('APP_USER_PEPPER is not configured');
    }

    return createHmac('sha256', pepper)
      .update(username.trim().toLowerCase())
      .digest('hex');
  }

  hashPassword(password: string, salt: string): string {
    const pepper = process.env.APP_USER_PEPPER;

    if (!pepper) {
      throw new Error('APP_USER_PEPPER is not configured');
    }

    return scryptSync(password + pepper, salt, 64).toString('hex');
  }

  async createUser(username: string, password: string) {
    const usernameHash = this.hashUsername(username);
    const salt = randomBytes(16).toString('hex');
    const passwordHash = this.hashPassword(password, salt);

    await this.pool.query(
      `
      INSERT INTO app_users (username_hash, password_hash, password_salt)
      VALUES ($1, $2, $3)
      ON CONFLICT (username_hash) DO NOTHING
      `,
      [usernameHash, passwordHash, salt],
    );

    return { created: true };
  }

  async validateUser(username: string, password: string) {
    const usernameHash = this.hashUsername(username);

    const result = await this.pool.query(
      `
      SELECT password_hash, password_salt
      FROM app_users
      WHERE username_hash = $1
      LIMIT 1
      `,
      [usernameHash],
    );

    const user = result.rows[0];

    if (!user) {
      throw new UnauthorizedException('Invalid username or password');
    }

    const attemptedHash = this.hashPassword(password, user.password_salt);

    const actualBuffer = Buffer.from(attemptedHash, 'hex');
    const expectedBuffer = Buffer.from(user.password_hash, 'hex');

    const matches =
      actualBuffer.length === expectedBuffer.length &&
      timingSafeEqual(actualBuffer, expectedBuffer);

    if (!matches) {
      throw new UnauthorizedException('Invalid username or password');
    }

    return { authenticated: true };
  }
}