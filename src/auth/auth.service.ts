import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient, User } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import { envs } from 'src/config';
import { LoginUserDto } from './dto/login-user.dto';
import { RegisterUserDto } from './dto/register.user.dto';
import { IJwtPayload } from './interface/jwt-payload.interface';
@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB connected');
  }

  async register(registerUserDto: RegisterUserDto) {
    // because prisma doesn't work well with mongoDB, don't recognize the @unique decorator, so we need to check if the user already exists
    try {
      const userExists = await this.user.findUnique({
        where: {
          email: registerUserDto.email,
        },
      });
      if (userExists) {
        this.logger.error('USER_ALREADY_EXISTS');
        throw new RpcException({
          status: 400,
          message: 'USER_ALREADY_EXISTS',
        });
      }

      const newUser = await this.user.create({
        data: {
          name: registerUserDto.name,
          email: registerUserDto.email,
          password: bcrypt.hashSync(registerUserDto.password, 10),
        },
      });
      const { password: __, ...rest } = newUser;
      return {
        user: rest,
        token: 'asd',
      };
    } catch (error) {
      if (error.message.includes('USER_ALREADY_EXISTS')) {
        throw new RpcException({
          status: 400,
          message: 'USER_ALREADY_EXISTS',
        });
      }
      // handle other errors
      this.logger.error('ERROR_CREATING_USER:', error);
      throw new RpcException({
        status: 400,
        message: 'ERROR_CREATING_USER',
      });
    }
  }

  async login(loginUserDto: LoginUserDto) {
    let user: User;
    try {
      user = await this.user.findUnique({
        where: {
          email: loginUserDto.email,
        },
      });
    } catch (error) {
      this.logger.error('ERROR_FINDING_USER:', error);
      throw new RpcException({
        status: 404,
        message: 'ERROR_FINDING_USER',
      });
    }

    if (!user) {
      this.logger.error('USER_NOT_FOUND');
      throw new RpcException({
        status: 404,
        message: 'USER_NOT_FOUND',
      });
    }
    if (!bcrypt.compareSync(loginUserDto.password, user.password)) {
      this.logger.error('INVALID_PASSWORD');
      throw new RpcException({
        status: 400,
        message: 'INVALID_PASSWORD',
      });
    }
    const { password: __, ...rest } = user;
    return {
      user: rest,
      token: await this.signJWT(rest),
    };
  }

  async signJWT(payload: IJwtPayload) {
    return this.jwtService.sign(payload);
  }
  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });
      return { user, token: await this.signJWT(user) };
    } catch (error) {
      this.logger.error('INVALID_TOKEN');
      throw new RpcException({
        status: 401,
        message: 'INVALID_TOKEN',
      });
    }
  }
}
