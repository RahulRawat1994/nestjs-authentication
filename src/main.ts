import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import helmet from 'helmet';
import * as express from 'express';
import { join } from 'path';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { writeFileSync } from 'fs';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  app.use(
    helmet.contentSecurityPolicy({
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'https://cdn.redoc.ly'],
      },
    }),
  );
  app.enableCors();
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  const config = new DocumentBuilder()
    .setTitle('NestJS Authentication API')
    .setDescription(
      `This is a secure and modular authentication API built with NestJS. It provides endpoints for user registration, login, email verification, password reset, OAuth (Google), and account management.

      Key Features:
      - JWT-based authentication and token refresh
      - Email verification and password recovery flows
      - Social login support (Google)
      - User profile and account management
      - Built with modular controllers and DTO validation

      Use the Authorize button to test secured routes with a valid JWT token.
      `
    )
    .setVersion('1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'Authorization',
        in: 'header',
      },
      'access-token',
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);

  // Optionally write to file for external use
  writeFileSync('./openapi-spec.json', JSON.stringify(document, null, 2));

  // If you still want Swagger UI (optional)
  SwaggerModule.setup('api/docs', app, document);

  app.use(
    '/openapi-spec.json',
    express.static(join(__dirname, '..', 'openapi-spec.json')),
  );
  await app.listen(3000);
}
bootstrap();
