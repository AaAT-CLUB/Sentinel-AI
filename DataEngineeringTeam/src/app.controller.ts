import { Controller, Get, Post, UseGuards } from '@nestjs/common';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { AppService } from './app.service';
import { ApiKeyGuard } from './auth.guard';
import { LogsService } from './logs.service';

@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly logsService: LogsService,
  ) {}

  @Get()
  getRoot() {
    return { message: 'Sentinel AI Data Engineering API' };
  }

  // 30 health checks per IP per minute
  @Get('health')
  @UseGuards(ThrottlerGuard)
  @Throttle({ 'db-default': { ttl: 60_000, limit: 30 } })
  getHealth() {
    return this.appService.getHealth();
  }

  // 20 reads per IP per minute to prevent DB read overload
  @Get('vulnerabilities')
  @UseGuards(ThrottlerGuard)
  @Throttle({ 'db-default': { ttl: 60_000, limit: 20 } })
  async getVulnerabilities() {
    return this.appService.getVulnerabilities();
  }

  // 5 imports per IP per minute — expensive: hits NVD API + bulk DB write
  @Post('import-cves')
  @UseGuards(ApiKeyGuard, ThrottlerGuard)
  @Throttle({ 'db-default': { ttl: 60_000, limit: 5 } })
  async importCves() {
    return this.appService.importCVEs();
  }

  // Admin-only: returns the last 1000 request log entries
  @Get('logs')
  @UseGuards(ApiKeyGuard)
  getLogs() {
    return this.logsService.getAll();
  }
}
