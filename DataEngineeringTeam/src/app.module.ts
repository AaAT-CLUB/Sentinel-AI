import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { Pool } from 'pg';
import { AppController } from './app.controller';
import { AppService } from './app.service';

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
    {
      // Provide a shared PostgreSQL connection pool to the application.
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
