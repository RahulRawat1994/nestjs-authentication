// auth.module.ts
import { Injectable, Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PassportModule } from '@nestjs/passport';
import { GoogleStrategy } from './google.strategy';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../user/entity/user.entity';
import { Session } from '../user/entity/session.entity';
import { VerificationToken } from '../user/entity/verification_token.entity';
import { AccessTokenBlacklist } from '../user/entity/access_token_blacklist';
import { UserModule } from '../user/user.module';
import { MailModule } from '../mail/mail.module';
import { UserService } from 'src/user/user.service';
import { SocialAccountService } from './social_account.service';
import { SocialAccount } from 'src/user/entity/social_account.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      User,
      Session,
      VerificationToken,
      AccessTokenBlacklist,
      SocialAccount,
    ]),
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'super-secret-key',
    }),
    UserModule,
    MailModule,
    PassportModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, GoogleStrategy, SocialAccountService],
  exports: [AuthService],
})
export class AuthModule {}
