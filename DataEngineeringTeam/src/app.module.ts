import { Module } from '@nestjs/common';
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { Pool } from 'pg';
import { AllExceptionsFilter } from './all-exceptions.filter';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ApiKeyService } from './api-key.service';
import { ApiKeyGuard } from './auth.guard';
import { LoggingInterceptor } from './logging.interceptor';
import { LogsService } from './logs.service';

@Module({
  imports: [
    ThrottlerModule.forRoot([
      {
        name: 'db-default',
        ttl: 60_000,
        limit: 60,
      },
    ]),
  ],
  controllers: [AppController],
  providers: [
    AppService,
    ApiKeyService,
    LogsService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    {
      provide: APP_GUARD,
      useClass: ApiKeyGuard,
    },
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: LoggingInterceptor,
    },
    {
      provide: 'PG_POOL',
      useFactory: () =>
        new Pool({
          host: process.env.DB_HOST,
          port: Number(process.env.DB_PORT),
          database: process.env.DB_NAME,
          user: process.env.DB_USER,
          password: process.env.DB_PASSWORD,
        }),
    },
  ],
})
export class AppModule {}
