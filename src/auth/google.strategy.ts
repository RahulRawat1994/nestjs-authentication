import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { UserService } from 'src/user/user.service';
import { SocialAccountService } from './social_account.service';
import axios from 'axios';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private readonly userService: UserService,
    private readonly socialAccountService: SocialAccountService,
  ) {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.APP_URL}/auth/google/callback`,
      scope: ['email', 'profile'],
    });
  }

  async validate(accessToken: string, refreshToken: string, profile: any, done: VerifyCallback): Promise<any> {
    const { name, emails, photos } = profile;
    const email = emails[0].value;

    // Check if the user already exists based on email
    let user = await this.userService.findByEmail(email);

    if (!user) {
      // If user doesn't exist, create a new user
      user = await this.userService.create({
        email,
        username: name.givenName,
        avatar: photos[0]?.value,
        provider: 'google',
        isVerified: true,
      });
    }

    // Check if Google social account already exists
    let socialAccount = await this.socialAccountService.findByProviderAndId('google', profile.id);

    if (!socialAccount) {
      // If no social account exists, link it
      socialAccount = await this.socialAccountService.create({
        user: user,
        provider: 'google',
        providerId: profile.id,
        avatar: photos[0]?.value,
        accessToken, // Store the Google Access Token
        refreshToken, // Store the Google Refresh Token
      });
    }

    // Pass user to the next step
    done(null, user);
  }

  async refreshGoogleAccessToken(refreshToken: string) {
    const response = await axios.post(
      'https://oauth2.googleapis.com/token',
      new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
      }),
    );
  
    return response.data; // { access_token, expires_in, token_type }
  }
}
