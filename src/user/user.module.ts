import { Module } from '@nestjs/common';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entity/user.entity';
import { Session } from './entity/session.entity';
import { VerificationToken } from './entity/verification_token.entity';
import { AccessTokenBlacklist } from './entity/access_token_blacklist';
import { UserRepository } from './user.repository';
@Module({
  imports: [
    TypeOrmModule.forFeature([
      User,
      Session,
      VerificationToken,
      AccessTokenBlacklist,
    ]),
  ],
  controllers: [UserController],
  providers: [UserService, UserRepository],
  exports: [UserRepository],
})
export class UserModule {}
