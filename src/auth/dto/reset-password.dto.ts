import {
  IsNotEmpty,
  MaxLength,
  Matches,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class resetPasswordDto {

  @IsNotEmpty()
  @ApiProperty({
    description: 'User ID for password reset',
    example: 1,
  })
  userId: number;

  @IsNotEmpty()
  @ApiProperty({
    description: 'Password reset token',
    example: 'abc123xyz456',
  })
  token: string;

  @IsNotEmpty()
  @MaxLength(100)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and be at least 8 characters long',
  })
  @ApiProperty({
    description: 'New password for the user',
    example: 'P@ssw0rd123',
  })
  newPassword: string;
}
