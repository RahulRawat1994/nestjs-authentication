import { IsEmail, IsNotEmpty, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
export class verifyEmailDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'Invalid email address' })
  @MaxLength(50)
  @ApiProperty({
    description: 'Email address for verification',
    example: 'test@example.com',
  })
  readonly email: string;

  @IsNotEmpty()
  @MaxLength(6)
  @ApiProperty({
    description: 'Verification code sent to the email',
    example: '123456',
  })
  readonly code: string;
}
