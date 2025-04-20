import { Module } from '@nestjs/common';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entity/user.entity';
import { Session } from './entity/session.entity';
import { VerificationToken } from './entity/verification_token.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User, Session, VerificationToken])],
  controllers: [UserController],
  providers: [UserService],
})
export class UserModule {}
