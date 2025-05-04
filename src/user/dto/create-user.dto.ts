import {
  IsEmail,
  IsNotEmpty,
  MinLength,
  MaxLength,
  Matches,
  IsOptional,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {
  @IsNotEmpty()
  @MinLength(3)
  @MaxLength(20)
  @Matches(/^[a-zA-Z0-9]+$/, {
    message: 'Username can only contain letters and numbers',
  })
  @ApiProperty({
    description: 'Username for the user',
    example: 'johndoe',
  })
  username: string;

  @IsNotEmpty()
  @IsEmail({}, { message: 'Invalid email address' })
  @MaxLength(50)
  @ApiProperty({
    description: 'Email address for the user',
    example: 'test@yopmail.com',
  })
  readonly email: string;

  @IsOptional()
  @MaxLength(100)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and be at least 8 characters long',
  })
  @ApiProperty({
    description: 'Password for the user',
    example: 'P@ssw0rd123',
  })
  password?: string;

  @IsOptional()
  @ApiProperty({
    description: 'Avatar URL for the user',
    example: 'https://example.com/avatar.jpg',
  })
  avatar?: string;

  @IsOptional()
  @ApiProperty({
    description: 'Provider for the user',
    example: 'google',
  })
  provider?: string;

  @IsOptional()
  @ApiProperty({
    description: 'Is the user verified?',
    example: true,
  })
  isVerified?: boolean;
}
