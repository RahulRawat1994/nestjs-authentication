import { IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class logoutDto {
  @IsNotEmpty()
  @ApiProperty({
    description: 'Refresh token for logout',
    example: '22klj35khk2gasjhgjkhgk2j3h4g',
  })
  refresh_token: string;
}
