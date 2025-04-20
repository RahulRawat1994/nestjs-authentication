
export class UpdateUserDto {
  readonly username?: string;
  readonly email?: string;
  readonly password?: string;
  readonly is_active?: boolean;
  readonly is_verified?: boolean;
}