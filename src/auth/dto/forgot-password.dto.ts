import {
  IsEmail,
  IsNotEmpty,
  MaxLength
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
export class forgotPasswordDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'Invalid email address' })
  @MaxLength(50)
  @ApiProperty({
    description: 'Email address for password reset',
    example: 'test@example.com',
  })
  readonly email: string;
}
