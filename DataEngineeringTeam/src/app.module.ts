import { Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { ThrottlerModule } from '@nestjs/throttler';
import { Pool } from 'pg';
import { AppController } from './app.controller';
import { AppService } from './app.service';
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
    LogsService,
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
