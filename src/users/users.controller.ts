import { Controller, Get, Post, Body, Param, Req } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { Request } from 'express';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post('register')
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @Post('login')
  login(@Body() createUserDto) {
    const { email, password } = createUserDto;
    return this.usersService.loginUser(email, password);
  }

  @Post('refresh')
  refresh(@Req() request: Request) {
    const [type, token] = request.headers['authorization']?.split(' ') || [];
    return this.usersService.refreshToken(token);
  }

  @Get()
  findAll() {
    return this.usersService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }
}
