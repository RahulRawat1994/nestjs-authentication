import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AccessTokenBlacklist } from '../user/entity/access_token_blacklist';

@Injectable()
export class TokenCleanupService {
  private readonly logger = new Logger(TokenCleanupService.name);

  constructor(
    @InjectRepository(AccessTokenBlacklist)
    private tokenRepo: Repository<AccessTokenBlacklist>,
  ) {}

  @Cron(CronExpression.EVERY_HOUR)
  async handleTokenCleanup() {
    const now = new Date();

    const result = await this.tokenRepo
      .createQueryBuilder()
      .delete()
      .where('expiresAt < :now', { now })
      .execute();

    this.logger.log(`Cleaned up ${result.affected} expired tokens`);
  }
}
