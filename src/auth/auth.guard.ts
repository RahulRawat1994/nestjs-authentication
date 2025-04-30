import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Request } from 'express';
import { AccessTokenBlacklist } from 'src/user/entity/access_token_blacklist';
import { Repository } from 'typeorm';

@Injectable()
export class JwtGuard implements CanActivate {
  constructor(
    @InjectRepository(AccessTokenBlacklist)
    private readonly tokenBlacklistService: Repository<AccessTokenBlacklist>,
    private readonly jwtService: JwtService,
  ) {}


  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromRequest(request);

    if (!token) {
      throw new UnauthorizedException('Authorization: Token not found');
    }

    const payload = await this.jwtService.verifyAsync(token, {
      secret: process.env.JWT_SECRET,
    });

    if (!payload) {
      throw new UnauthorizedException('Invalid token');
    }

    // Check if the token is blackliste
    const isBlacklisted = await this.tokenBlacklistService.findOne({
      where: { token },
    });
    if (isBlacklisted) {
      throw new UnauthorizedException('Token is blacklisted');
    }

    // update the request object with the user information
    request['user'] = payload; 
    return true;
  }

  private extractTokenFromRequest(request: any): string {
    const authHeader = request.headers['authorization'];
    if (!authHeader) return null;
    return authHeader.replace('Bearer ', '');
  }

}
