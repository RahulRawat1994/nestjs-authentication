import {
  IsNotEmpty,
  MaxLength,
  Matches,
} from 'class-validator';

export class resetPasswordDto {

  @IsNotEmpty()
  userId: number;

  @IsNotEmpty()
  token: string;

  @IsNotEmpty()
  @MaxLength(100)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and be at least 8 characters long',
  })
  newPassword: string;
}
