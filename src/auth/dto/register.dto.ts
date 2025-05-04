import {
  IsEmail,
  IsNotEmpty,
  MinLength,
  MaxLength,
  Matches,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class registerDto {
  @IsNotEmpty()
  @MinLength(3)
  @MaxLength(20)
  @Matches(/^[a-zA-Z0-9]+$/, {
    message: 'Username can only contain letters and numbers',
  })
  @ApiProperty({
    description: 'Username for registration',
    example: 'johndoe',
  })
  username: string;

  @IsNotEmpty()
  @IsEmail({}, { message: 'Invalid email address' })
  @MaxLength(50)
  @ApiProperty({
    description: 'Email address for registration',
    example: 'test@exmaple.com',
  })
  readonly email: string;

  @IsNotEmpty()
  @MaxLength(100)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and be at least 8 characters long',
  })
  @ApiProperty({
    description: 'Password for registration',
    example: 'P@ssw0rd123',
  })
  password: string;
}
