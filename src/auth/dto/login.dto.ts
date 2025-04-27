import {
  IsNotEmpty,
  MinLength,
  MaxLength,
  Matches,
} from 'class-validator';

export class loginDto {
  @IsNotEmpty() @MinLength(3) @MaxLength(20) @Matches(/^[a-zA-Z0-9]+$/, {
    message: 'username can only contain letters and numbers',
  }) username: string;

  @IsNotEmpty()
  @MaxLength(100)
  password: string;
}
