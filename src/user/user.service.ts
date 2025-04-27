import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserResponseDto } from './dto/user-response.dto';
import { User } from './entity/user.entity';
import { plainToInstance } from 'class-transformer';
import { UserRepository } from './user.repository';

@Injectable()
export class UserService {
  private readonly SALT_ROUNDS: number = 10;

  constructor(private readonly userRepository: UserRepository) {}

  /**
   * Create a new user
   * @param dto - User data
   * @returns Created user object
   */
  async create(dto: CreateUserDto): Promise<User> {
    const hashedPassword: string = await this.userRepository.hashPassword(dto.password);
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
    try {
      const users = await this.userRepository.find();

      const safeUsers = plainToInstance(UserResponseDto, users, {
        excludeExtraneousValues: true,
      }) as UserResponseDto[];

      return safeUsers;
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error('Failed to fetch users:', error.message);
      } else {
        console.error('Unknown error fetching users:', error);
      }
      throw error;
    }
  }

  /**
   * Update a user by ID
   * @param id {number} - User ID
   * @param dto {UpdateUserDto} - User data to update
   * @returns Updated user object
   */
  async update(id: number, dto: UpdateUserDto): Promise<User> {
    // check if user exists
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new Error('User not found');
    }
    // check if password is being updated
    if (dto.password) {
      const hashedPassword: string = await this.userRepository.hashPassword(dto.password);
      if (!hashedPassword) {
        throw new Error('Error hashing password');
      }
      (
        dto as Partial<CreateUserDto & { password_hash: string }>
      ).password_hash = hashedPassword;
      delete dto.password;
    }
    // update user
    await this.userRepository.update(id, dto);
    // return updated user
    return this.userRepository.findOne({ where: { id } });
  }
}
