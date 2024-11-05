import {
  ConflictException,
  HttpStatus,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';

import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

type Tokens = {
  access_token: string;
  refresh_token: string;
};

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwt: JwtService,
  ) {}

  async create(createUserDto: CreateUserDto) {
    try {
      const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
      const newUser = new this.userModel({
        ...createUserDto,
        password: hashedPassword,
      });
      const user = await newUser.save();
      const { access_token, refresh_token } = await this.generateTokens(user);

      return {
        access_token,
        refresh_token,
        user: this.removePassword(user),
        status: HttpStatus.CREATED,
        messege: 'User created succesfully',
      };
    } catch (error) {
      throw new ConflictException('Duplicidad', {
        description: 'El usuario ya existe',
        cause: error,
      });
    }
  }

  private removePassword(user) {
    const { password, ...res } = user.toObject();
    return res;
  }

  async loginUser(email: string, password: string) {
    try {
      const user = await this.userModel.findOne({ email });
      if (!user) {
        throw new UnauthorizedException('Credenciales incorrectas');
      }
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        throw new UnauthorizedException('Credenciales incorrectas');
      }
      const payload = { sub: user.id, email: user.email, name: user.name };
      const { access_token, refresh_token } =
        await this.generateTokens(payload);
      return {
        access_token,
        refresh_token,
        user: this.removePassword(user),
        message: 'Login Successful',
      };
    } catch (error) {
      throw new UnauthorizedException('Error de autenticación', {
        cause: error,
        description: 'No se pudo autenticar el usuario',
      });
    }
  }

  async refreshToken(refreshToken: string) {
    try {
      const user = this.jwt.verify(refreshToken, {
        secret: 'jw_secret_refresh',
      });
      const payload = { sub: user._id, email: user.email, name: user.name };
      const { access_token, refresh_token } =
        await this.generateTokens(payload);
      return {
        access_token,
        refresh_token,
        status: 200,
        message: 'refresh token succesfull',
      };
    } catch (error) {
      throw new UnauthorizedException('Error de autenticación', {
        cause: error,
        description: 'No se pudo refrescar el token',
      });
    }
  }

  private async generateTokens(user): Promise<Tokens> {
    const jwtPayload = { sub: user._id, email: user.email, name: user.name };
    const [access_token, refresh_token] = await Promise.all([
      this.jwt.signAsync(jwtPayload, {
        secret: 'jw_secret',
        expiresIn: '1d',
      }),
      this.jwt.signAsync(jwtPayload, {
        secret: 'jw_secret_refresh',
        expiresIn: '3d',
      }),
    ]);
    return { access_token, refresh_token };
  }

  findAll() {
    return `This action returns all users`;
  }

  async findOne(id: string): Promise<User> {
    try {
      const user = await this.userModel.findOne({ _id: id });
      if (!user) {
        throw new NotFoundException('Usuario no encontrado');
      }
      return user;
    } catch (error) {
      throw new NotFoundException('Usuario no encontrado', {
        cause: error,
        description: 'No se pudo encontrar un usuario con el ID proporcionado',
      });
    }
  }
}
