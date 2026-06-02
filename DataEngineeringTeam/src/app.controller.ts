import { Controller, Get, Post, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { ApiKeyGuard } from './auth.guard';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getRoot() {
    return { message: 'Sentinel AI Data Engineering API' };
  }

  @Get('health')
  getHealth() {
    return this.appService.getHealth();
  }

  @Get('vulnerabilities')
  async getVulnerabilities() {
    return this.appService.getVulnerabilities();
  }

  @Post('import-cves')
  @UseGuards(ApiKeyGuard)
  async importCves() {
    return this.appService.importCVEs();
  }
}
