# NestJS Authentication Boilerplate

A complete authentication system built with **NestJS** including:
- User Registration and Login
- Email Verification
- Forgot Password & Reset Password
- JWT Authentication
- Request Throttling (Rate Limiting)
- Pug Templated Email Sending
- TypeORM + PostgreSQL (or other databases)

---

## 🚀 Features

- 🔒 Secure password hashing (bcrypt)
- ✉️ Email verification with expiring tokens
- 🔑 JWT access tokens
- 🧹 Clean architecture (services, repositories, DTOs)
- 🕒 Throttling to prevent brute force attacks
- 📄 Pug template engine for email templates
- 📦 Environment-based configuration (.env)

---

## 🛠️ Tech Stack

- **NestJS** (TypeScript)
- **TypeORM** (Database ORM)
- **PostgreSQL** (default database)
- **@nestjs/jwt** (JWT authentication)
- **@nestjs/throttler** (Rate limiting)
- **@nestjs-modules/mailer** (Email sending)
- **Pug** (HTML email templating)
- **Dayjs** (Date/time management)

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/RahulRawat1994/nestjs-authentication.git
cd nestjs-authentication
```


```bash
$ npm install
```

## Compile and run the project

```bash
# development
$ npm run start

# watch mode
$ npm run start:dev

# production mode
$ npm run start:prod
```

## Run tests

```bash
# unit tests
$ npm run test

# e2e tests
$ npm run test:e2e

# test coverage
$ npm run test:cov
```
