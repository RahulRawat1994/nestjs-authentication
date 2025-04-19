import {
  Controller,
  Post,
  Get,
  Put,
  Delete,
  Body,
  Param,
} from '@nestjs/common';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { UpdateUserDto } from './dto/update-user.dto'

@Controller('user')
export class UserController {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  @Get()
  getUsers() {
    return this.userRepository.find();
  }

  @Get(':id')
  getUserById(@Param('id') id: number) {
    return this.userRepository.findOne({ where: { id } });
  }

  @Post()
  createUser(@Body() body: Partial<User>) {
    const user = this.userRepository.create(body);
    return this.userRepository.save(user);
  }

  @Put(':id')
  async updateUser(@Param('id') id: number, @Body() body: UpdateUserDto) {
    await this.userRepository.update(id, body);
    return this.userRepository.findOne({ where: { id } });
  }

  @Delete(':id')
  deleteUser(@Param('id') id: number) {
    return this.userRepository.delete(id);
  }
}
