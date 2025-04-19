
export class UpdateUserDto {
  readonly username?: string;
  readonly email?: string;
  readonly password_hash?: string;
  readonly is_active?: boolean;
  readonly is_verified?: boolean;
}