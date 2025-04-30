import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
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

  // Create a new social account link
  async create(createSocialAccountDto: any): Promise<SocialAccount> {
    const socialAccount = this.socialAccountRepository.create(createSocialAccountDto);
    return this.socialAccountRepository.save(socialAccount);
  }
}
