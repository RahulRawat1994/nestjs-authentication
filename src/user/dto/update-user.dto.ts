import { IsOptional, IsString, IsBoolean, IsEmail } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UpdateUserDto {
  @IsOptional()
  @IsString()
  @ApiProperty({
    description: 'Username of the user',
    example: 'johndoe',
  })
  username?: string;

  @IsOptional()
  @IsEmail()
  @ApiProperty({
    description: 'Email address of the user',
    example: 'test@yopamil.com',
  })
  email?: string;

  @IsOptional()
  @IsString()
  @ApiProperty({
    description: 'Avatar URL of the user',
    example: 'https://example.com/avatar.jpg',
  })
  password?: string;

  @IsOptional()
  @IsBoolean()
  @ApiProperty({
    description: 'Indicates if the user is active',
    example: true,
  })
  is_active?: boolean;

  @IsOptional()
  @IsBoolean()
  @ApiProperty({
    description: 'Indicates if the user is verified',
    example: true,
  })
  is_verified?: boolean;
}
