import 'reflect-metadata';
import 'dotenv/config';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { AppModule } from './app.module';

// Bootstraps and starts the NestJS application using Fastify as the HTTP server.
// This file is the entry point for the API and will listen on port 3000.
async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(AppModule, new FastifyAdapter());
  await app.listen(3000, '0.0.0.0');
  console.log('🚀 API running at http://localhost:3000');
}

bootstrap();
