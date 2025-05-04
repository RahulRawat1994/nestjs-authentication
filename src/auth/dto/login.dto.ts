import {
  IsNotEmpty,
  MinLength,
  MaxLength,
  Matches,
  IsOptional,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class loginDto {
  @IsNotEmpty()
  @MinLength(3)
  @MaxLength(20)
  @Matches(/^[a-zA-Z0-9]+$/, {
    message: 'username can only contain letters and numbers',
  })
  @ApiProperty({
    description: 'Username for login',
    example: 'john_doe',
  })
  username: string;

  @IsNotEmpty()
  @MaxLength(100)
  @ApiProperty({
    description: 'Password for login',
    example: 'P@ssw0rd123',
  })
  password: string;

  @IsOptional()
  @ApiProperty({
    description: 'Remember me option',
    example: true,
  })
  rememberMe?: boolean;
}
