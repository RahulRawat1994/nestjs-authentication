import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Session } from '../user/entity/session.entity';
import { VerificationToken } from '../user/entity/verification_token.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { loginDto } from './dto/login.dto';
import { registerDto } from './dto/register.dto';
import { forgotPasswordDto } from './dto/forgot-password.dto';
import { resetPasswordDto } from './dto/reset-password.dto';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import * as dayjs from 'dayjs';
import { UserRepository } from '../user/user.repository';
import { MailService } from '../mail/mail.service';
import { UserService } from 'src/user/user.service';
import { plainToInstance } from 'class-transformer';
import { UserResponseDto } from 'src/user/dto/user-response.dto';

@Injectable()
export class AuthService {
  [x: string]: any;
  constructor(
    @InjectRepository(Session)
    private readonly sessionRepository: Repository<Session>,
    @InjectRepository(VerificationToken)
    private readonly verificationTokenRepository: Repository<VerificationToken>,
    private readonly jwtService: JwtService,
    private readonly userRepository: UserRepository,
    private readonly userService: UserService,
    private readonly mailService: MailService,
  ) {}

  async login(dto: loginDto, userAgent: string, ip: string) {
    const user = await this.userRepository.findOne({
      where: [{ username: dto?.username, is_active: true, deleted_at: null }],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }
    const isPasswordValid = await this.userRepository.comparePassword(
      dto.password,
      user.password_hash,
    );
    if (!isPasswordValid) {
      throw new BadRequestException('Invalid password');
    }
    if (!user.is_verified) {
      throw new NotFoundException('Email not verified');
    }

    // Generate JWT token or session here
    const payload = { sub: user.id, username: user.username };

    // Set token expiration based on rememberMe
    const accessTokenExpiresIn = process.env.ACCESS_TOKEN_EXPIRES_IN || '15m'; // Access token short-lived always
    const refreshTokenExpiresIn =
      (dto.rememberMe
        ? process.env.REFRESH_TOKEN_EXPIRES_IN
        : process.env.REFRESH_TOKEN_LONG_LIVED) || 30; // Refresh token long-lived

    const accessToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_SECRET,
      expiresIn: accessTokenExpiresIn,
    });
    const refreshToken = uuidv4(); // UUID for refresh token
    const expiresAt = dayjs()
      .add(Number(refreshTokenExpiresIn), 'days')
      .toDate(); // 30 days expiry

    // Save session
    const session = this.sessionRepository.create({
      user,
      refresh_token: refreshToken,
      user_agent: userAgent,
      ip_address: ip,
      expires_at: expiresAt,
    });

    await this.sessionRepository.save(session);

    return {
      status: 'success',
      message: 'Login successful',
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
      },
    };
  }

  async register(dto: registerDto) {
    const hashedPassword: string = await this.userRepository.hashPassword(dto.password);
    if (!hashedPassword) {
      throw new BadRequestException('Error hashing password');
    }
    // // Check if the user already exists
    const existingUser = await this.userRepository.findOne({
      where: [{ username: dto.username }, { email: dto.email }],
    });
    if (existingUser) {
      throw new BadRequestException('User with this username or email already exists');
    }

    const user = this.userRepository.create({
      ...dto,
      password_hash: hashedPassword,
    });

    // Save user to database first
    const savedUser = await this.userRepository.save(user);

    this.sendVerificationEmail(savedUser);
    // Send verification email

    const safeUser = plainToInstance(
      UserResponseDto,
      { ...savedUser },
      {
        excludeExtraneousValues: true,
      },
    );
    return safeUser;

  }

  private async sendVerificationEmail(user) {
    // Generate a verification token
    const verificationToken = this.verificationTokenRepository.create({
      user,
      token: uuidv4(), // generates a unique token
      type: 'email_verification',
      expires_at: dayjs().add(60, 'minute').toDate(), // expires in 60 minutes
    });

    // Save verification token
    await this.verificationTokenRepository.save(verificationToken);

    await this.mailService.sendEmail({
      subject: 'Welcome to the realm of NestJS',
      template: 'signup-confirmation-email',
      context: {
        name: user.username,
        verificationLink: `${process.env.APP_URL}/auth/verify-email/${user.id}/${verificationToken.token}`,
      },
      emails: [user.email],
    });
  }

  async forgotPassword(dto: forgotPasswordDto) {
    // Find user by email
    const user = await this.userRepository.findOne({
      where: { email: dto.email },
    });

    if (!user) {
      throw new Error('No user found with this email');
    }

    // Create password reset token
    const resetToken = this.verificationTokenRepository.create({
      user: user,
      token: uuidv4(),
      type: 'password_reset',
      expires_at: dayjs().add(15, 'minute').toDate(), // Reset token expires in 15 minutes
    });

    // Save token
    await this.verificationTokenRepository.save(resetToken);

    // Send password reset email
    await this.mailService.sendEmail({
      subject: 'Password Reset Request',
      template: 'reset-password-email',
      context: {
        name: user.username,
        resetLink: `${process.env.APP_URL}/auth/reset-password/${user.id}/${resetToken.token}`,
      },
      emails: [user.email],
    });

    return {
      status: 'success',
      message: 'Password reset instructions sent to your email',
    };
  }

  async resetPassword(dto: resetPasswordDto) {
    const { userId, token, newPassword } = dto;

    // Step 1: Find the user
    const user = await this.userRepository.findOne({
      where: { id: userId },
      relations: ['verification_tokens'],
    });

    if (!user) {
      throw new Error('User not found');
    }

    // Find matching reset token
    const resetToken = user.verification_tokens.find(
      (vt) => vt.token === token && vt.type === 'password_reset',
    );

    if (!resetToken) {
      throw new BadRequestException('Invalid or expired password reset token');
    }

    // Check if token is expired
    if (dayjs().isAfter(dayjs(resetToken.expires_at))) {
      throw new BadRequestException('Password reset token has expired');
    }

    // Hash new password
    const hashedPassword = await this.userRepository.hashPassword(newPassword);
    if (!hashedPassword) {
      throw new BadRequestException('Failed to hash new password');
    }

    // Update user's password
    user.password_hash = hashedPassword;
    await this.userRepository.save(user);

    // Delete the used reset token
    await this.verificationTokenRepository.delete({ id: resetToken.id });

    return {
      status: 'success',
      message: 'Password successfully reset',
    };
  }

  async verifyEmail(id, token) {
    // Find the user by ID
    const user = await this.userRepository.findOne({
      where: { id },
      relations: ['verification_tokens'], // make sure to load tokens
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Step 2: Find matching verification token
    const verificationToken = user.verification_tokens.find(
      (vt) => vt.token === token && vt.type === 'email_verification',
    );

    if (!verificationToken) {
      throw new BadRequestException('Invalid or expired verification token');
    }

    // Step 3: Check if the token is expired
    if (dayjs().isAfter(dayjs(verificationToken.expires_at))) {
      throw new BadRequestException('Verification token has expired');
    }

    // Step 4: Mark the user as verified
    user.is_verified = true; // you need an "is_verified" boolean column on User entity
    user.is_active = true; // Optional: Activate the user
    await this.userRepository.save(user);

    // Step 5: Delete the used verification token (optional but cleaner)
    await this.verificationTokenRepository.delete({ id: verificationToken.id });

    return {
      status: 'success',
      message: 'Email successfully verified',
    };
  }

  async logout(userId: number, refresh_token: string) {
    try {
      if (!userId) {
        throw new NotFoundException('No user provided');
      }

      // Find the session by token
      const session = await this.sessionRepository.findOne({
        where: { refresh_token, user: { id: userId } },
      });

      if (!session) {
        throw new NotFoundException('Session not found or already logged out');
      }
      // Save token into Blacklist Table
      await this.sessionRepository.remove(session);

      return {
        status: 'success',
        message: 'Logged out successfully',
      };
    } catch (error) {
      return {
        status: 'error',
        message: error?.message ?? 'Logout failed',
      };
    }
  }

  async logoutAllDevices(userId: number) {
    if (!userId) {
      throw new NotFoundException('No user provided');
    }

    // Find all sessions for the user
    const sessions = await this.sessionRepository.find({
      where: { user: { id: userId } },
    });

    if (sessions.length === 0) {
      throw new NotFoundException('No active sessions found');
    }

    // Remove all sessions
    await this.sessionRepository.remove(sessions);

    return {
      status: 'success',
      message: 'Logged out from all devices successfully',
    };
  }

  async getProfile(userId: number) {
    const user = await this.userService.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }
    return {
      status: 'success',
      message: 'User profile retrieved successfully',
      user,
    };
  }

  async refreshToken(refreshToken: string, userAgent: string, ip: string) {
    // Find the session by refresh token
    const session = await this.sessionRepository.findOne({
      where: { refresh_token: refreshToken },
      relations: ['user'],
    });

    if (!session) {
      throw new NotFoundException('Session not found or already logged out');
    }

    // Check if the session is expired
    if (dayjs().isAfter(dayjs(session.expires_at))) {
      throw new BadRequestException('Session has expired');
    }

    // Generate new tokens
    const payload = { sub: session.user.id, username: session.user.username };
    const accessToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_SECRET,
    });
    const newRefreshToken = uuidv4(); // UUID for new refresh token
    const expiresAt = dayjs().add(30, 'days').toDate(); // 30 days expiry

    // Update session with new refresh token and expiry
    session.refresh_token = newRefreshToken;
    session.expires_at = expiresAt;
    session.user_agent = userAgent;
    session.ip_address = ip;

    await this.sessionRepository.save(session);

    return {
      status: 'success',
      message: 'Tokens refreshed successfully',
      accessToken,
      refreshToken: newRefreshToken,
      user: {
        id: session.user.id,
        username: session.user.username,
        email: session.user.email,
      },
    };
  }

  async deactivateAccount(userId: number) {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Deactivate the user
    user.is_active = false;
    await this.userRepository.save(user);
    await this.logoutAllDevices(userId); // Log out from all devices

    return {
      status: 'success',
      message: 'Account deactivated successfully',
    };
  }

  async deleteAccount(userId: number) {
    await this.userService.delete(userId);
    await this.logoutAllDevices(userId); // Log out from all devices
    return {
      message: 'Account deletion requested. Will be deleted after 30 days.',
    };
  }

  async restoreAccount(userId: number) {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (!user.deleted_at) {
      throw new BadRequestException('Account is not marked for deletion.');
    }

    const thirtyDaysAgo = dayjs().subtract(30, 'days').toDate();

    if (user.deleted_at < thirtyDaysAgo) {
      throw new BadRequestException(
        'Cannot restore. Account already scheduled for permanent deletion.',
      );
    }

    await this.userRepository.update(userId, { deleted_at: null });

    return { message: 'Account restored successfully.' };
  }

  loginWithGoogle(user: any) {
    const payload = { email: user.email, sub: user.id };
    const accessToken = this.jwtService.sign(payload, {
      expiresIn: '15m',
    });
    const refreshToken = uuidv4(); // or sign a refresh token too
    return { accessToken, refreshToken };
  }
}
