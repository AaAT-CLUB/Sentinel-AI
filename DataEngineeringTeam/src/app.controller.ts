import { Controller, Get, Post } from '@nestjs/common';
import { AppService } from './app.service';

// Main HTTP controller for the API. This class maps routes to service calls.
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
  async importCves() {
    return this.appService.importCVEs();
  }
}
