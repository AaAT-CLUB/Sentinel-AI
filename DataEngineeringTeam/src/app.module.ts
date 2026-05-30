import { Module } from '@nestjs/common';
import { Pool } from 'pg';
import { AppController } from './app.controller';
import { AppService } from './app.service';

// Root module for the NestJS application. It defines controllers and providers.
@Module({
  imports: [],
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
