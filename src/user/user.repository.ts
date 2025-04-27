// user.repository.ts
import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { User } from './entity/user.entity';

@Injectable()
export class UserRepository extends Repository<User> {
  private readonly SALT_ROUNDS: number = 10;

  constructor(@InjectDataSource() dataSource: DataSource) {
    super(User, dataSource.createEntityManager());
  }

  async findActiveUsers(): Promise<User[]> {
    return this.find({ where: { is_active: true } });
  }

  /**
   * Hash a password using bcrypt
   * @param password - Password to hash
   * @returns Promise of hashed password
   * @throws Error if hashing fails
   */
  async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(this.SALT_ROUNDS);
    try {
      return await bcrypt.hash(password, salt);
    } catch (error: unknown) {
      if (error instanceof Error) {
        throw new Error('Error hashing password: ' + error.message);
      }
      throw new Error('Error hashing password: Unknown error');
    }
  }
  /**
   * Compare a plain password with a hashed password
   * @param password - Password to compare
   * @param hashedPassword - Hashed password to compare against
   * @returns Promise of boolean indicating if the passwords match
   * @throws Error if comparison fails
   */
  async comparePassword(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }

  // Add more custom methods here
}
