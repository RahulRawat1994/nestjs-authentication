import {
  Controller,
  Post,
  Body,
  Req,
  Param,
  Get,
  UseGuards,
  HttpCode,
  HttpStatus,
  Delete,
} from '@nestjs/common';
import { Request } from 'express';
import { JwtGuard } from './auth.guard';
import { AuthGuard } from '@nestjs/passport';
import { loginDto } from './dto/login.dto';
import { AuthService } from './auth.service';
import { registerDto } from './dto/register.dto';
import { forgotPasswordDto } from './dto/forgot-password.dto';
import { resetPasswordDto } from './dto/reset-password.dto';
import { Throttle } from '@nestjs/throttler';
interface CustomRequest extends Request {
  user?: {
    id: any;
    sub: string;
  };
}

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
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

  @HttpCode(HttpStatus.OK)
  @Post('forgot-password')
  forgotPassword(@Body() body: forgotPasswordDto) {
    return this.authService.forgotPassword(body);
  }

  @HttpCode(HttpStatus.OK)
  @Post('reset-password')
  resetPassword(@Body() body: resetPasswordDto) {
    return this.authService.resetPassword(body);
  }

  @HttpCode(HttpStatus.OK)
  @Post('refresh-token')
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  async refreshToken(@Body() body: { refresh_token: string }, @Req() req: Request) {
    const userAgent = req.headers['user-agent'] || 'unknown';
    const ip = req.headers['x-forwarded-for']?.toString() || '0.0.0.0';

    return await this.authService.refreshToken(body.refresh_token, userAgent, ip);
  }

  @UseGuards(JwtGuard)
  @Get('logout')
  logout(@Body() body: { refresh_token: string }, @Req() req: Request) {
    console.log('Logout request received', req);
    try {
      const customReq = req as CustomRequest;
      const userId = +customReq.user?.sub;
      const refreshToken = body.refresh_token;
      if (!refreshToken) {
        throw new Error('Refresh token not provided');
      }
      if (!userId) {
        throw new Error('User not found');
      }
      return this.authService.logout(userId, refreshToken);
    } catch (error) {
      return {
        status: 'error',
        message: error?.message ?? 'Logout failed',
      };
    }
  }

  @UseGuards(JwtGuard)
  @Post('logout-all')
  async logoutAll(@Req() req: Request) {
    const userId = (req as CustomRequest).user.sub as unknown as number;
    return await this.authService.logoutAllDevices(userId);
  }

  @UseGuards(JwtGuard)
  @Get('profile')
  getProfile(@Req() req: Request) {
    const user = (req as CustomRequest).user;

    return this.authService.getProfile(user?.sub as unknown as number);
  }

  @UseGuards(JwtGuard)
  @Post('deactivate')
  deactivateAccount(@Req() req: CustomRequest) {
    const userId = req.user?.id;
    return this.authService.deactivate(userId);
  }

  @UseGuards(JwtGuard)
  @Delete('delete-account')
  async deleteAccount(@Req() req: CustomRequest) {
    const userId = req.user?.id;
    return this.authService.deleteAccount(userId);
  }

  @UseGuards(JwtGuard)
  @Post('restore-account')
  async restoreAccount(@Req() req: CustomRequest) {
    const userId = req.user.id;
    return this.authService.restoreAccount(userId);
  }



  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    // Redirects to Google
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  googleAuthRedirect(@Req() req) {
    // Handle the response after Google login
    return this.authService.loginWithGoogle(req.user);
  }

}
