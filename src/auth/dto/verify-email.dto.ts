import {
  IsEmail,
  IsNotEmpty,
  MaxLength,
} from 'class-validator';

export class verifyEmailDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'Invalid email address' })
  @MaxLength(50)
  readonly email: string;

  @IsNotEmpty()
  @MaxLength(6)
  readonly code: string;
}
