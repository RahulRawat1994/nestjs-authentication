import { Exclude, Expose } from 'class-transformer';

@Exclude() // 👈 exclude everything by default
export class UserResponseDto {
  @Expose()
  id: number;

  @Expose()
  username: string;

  @Expose()
  email: string;

  @Exclude() // 👈 not exposed = excluded
  password_hash: string;

  @Expose()
  is_active: boolean;

  @Expose()
  is_verified: boolean;

  @Expose()
  created_at: Date;

  @Expose()
  updated_at: Date;

  constructor(partial: Partial<UserResponseDto>) {
    Object.assign(this, partial);
  }
}
