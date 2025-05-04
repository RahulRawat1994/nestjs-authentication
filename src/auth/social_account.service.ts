import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { DeepPartial } from 'typeorm/common/DeepPartial';
import { SocialAccount } from 'src/user/entity/social_account.entity';

@Injectable()
export class SocialAccountService {
  constructor(
    @InjectRepository(SocialAccount)
    private readonly socialAccountRepository: Repository<SocialAccount>,
  ) {}

  // Find social account by provider and provider's unique ID (e.g., Google ID)
  async findByProviderAndId(provider: string, providerId: string): Promise<SocialAccount> {
    return this.socialAccountRepository.findOne({ where: { provider, providerId } });
  }

  async create(
    createSocialAccountDto: DeepPartial<SocialAccount>,
  ): Promise<SocialAccount> {
    const socialAccount = this.socialAccountRepository.create({
      ...createSocialAccountDto,
    });
    if (Array.isArray(socialAccount)) {
      throw new Error('Expected a single SocialAccount, but received an array.');
    }
    return this.socialAccountRepository.save(socialAccount);
  }
}
