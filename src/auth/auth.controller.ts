import {
  Controller,
  Post,
  Body,
  Req,
  Param,
  Get,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { AuthGuard } from './auth.guard';
import { loginDto } from './dto/login.dto';
import { AuthService } from './auth.service';
import { registerDto } from './dto/register.dto';
import { forgotPasswordDto } from './dto/forgot-password.dto';
import { resetPasswordDto } from './dto/reset-password.dto';
import { Throttle } from '@nestjs/throttler';
interface CustomRequest extends Request {
  user?: { sub: string };
}

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  async login(@Body() body: loginDto, @Req() req: Request) {
    const userAgent = req.headers['user-agent'] || 'unknown';
    const ip = req.headers['x-forwarded-for']?.toString() || '0.0.0.0';
    return await this.authService.login(body, userAgent, ip);
  }

  @Post('register')
  register(@Body() body: registerDto) {
    return this.authService.register(body);
  }

  @Get('verify-email/:id/:token')
  verifyEmail(@Param('id') id: number, @Param('token') token: string) {
    return this.authService.verifyEmail(id, token);
  }

  @Post('forgot-password')
  forgotPassword(@Body() body: forgotPasswordDto) {
    return this.authService.forgotPassword(body);
  }

  @Post('reset-password')
  resetPassword(@Body() body: resetPasswordDto) {
    return this.authService.resetPassword(body);
  }
  @UseGuards(AuthGuard)
  @Get('logout')
  logout(@Req() req: Request) {
    console.log('Logout request received', req);
    try {
      const customReq = req as CustomRequest;
      const userId = +customReq.user?.sub;

      if (!userId) {
        throw new Error('User not found');
      }
      return this.authService.logout(userId);
    } catch (error) {
      return {
        status: 'error',
        message: error?.message ?? 'Logout failed',
      };
    }
  }
}
