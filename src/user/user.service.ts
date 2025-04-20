import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserResponseDto } from './dto/user-response.dto';
import { User } from './entity/user.entity';
import { plainToInstance } from 'class-transformer';
import * as bcrypt from 'bcryptjs';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

@Injectable()
export class UserService {
  private readonly SALT_ROUNDS: number = 10;

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  /**
   * Hash a password using bcrypt
   * @param password - Password to hash
   * @returns Promise of hashed password
   * @throws Error if hashing fails
   */
  private async hashPassword(password: string): Promise<string> {
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
   * @returns 
   */
  private async comparePassword(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }

  /**
   * Create a new user
   * @param dto - User data
   * @returns Created user object
   */
  async create(dto: CreateUserDto): Promise<User> {
    const hashedPassword: string = await this.hashPassword(dto.password);
    if (!hashedPassword) {
      throw new Error('Error hashing password');
    }
    // // Check if the user already exists
    const existingUser = await this.userRepository.findOne({
      where: [{ username: dto.username }, { email: dto.email }],
    });
    if (existingUser) {
      throw new Error('User with this username or email already exists');
    }

    const user = this.userRepository.create({
      ...dto,
      password_hash: hashedPassword,
    });
    return this.userRepository.save(user);
  }

  /**
   * Delete a user by ID
   * @param id - User ID
   */
  async delete(id: number): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new Error('User not found');
    }
    await this.userRepository.remove(user);
  }

  /**
   * Find a user by ID
   * @param id - User ID
   * @returns User object or null if not found
   */
  async findById(id: number): Promise<UserResponseDto | null> {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) return null;

    const safeUser = plainToInstance(
      UserResponseDto,
      { ...user },
      {
        excludeExtraneousValues: true,
      },
    ) as UserResponseDto;
    return safeUser;
  }

  /**
   * Find all users
   * @returns Array of User objects
   */
  async find(): Promise<UserResponseDto[]> {
    return await this.userRepository.find();
  }

  /**
   * Update a user by ID
   * @param id {number} - User ID
   * @param dto {UpdateUserDto} - User data to update
   * @returns 
   */
  async update(id: number, dto: UpdateUserDto): Promise<User> {
    // check if user exists
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new Error('User not found');
    }
    // check if password is being updated
    if (dto.password) {
      const hashedPassword: string = await this.hashPassword(dto.password);
      if (!hashedPassword) {
        throw new Error('Error hashing password');
      }
      (
        dto as Partial<CreateUserDto & { password_hash: string }>
      ).password_hash = hashedPassword;
    }
    // update user
    await this.userRepository.update(id, dto);
    // return updated user
    return this.userRepository.findOne({ where: { id } });
  }
}
