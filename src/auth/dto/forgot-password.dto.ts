import {
  IsEmail,
  IsNotEmpty,
  MaxLength
} from 'class-validator';

export class forgotPasswordDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'Invalid email address' })
  @MaxLength(50)
  readonly email: string;
}
