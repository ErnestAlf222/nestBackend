import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';

// Dto
import { CreateUserDto, LoginDto, RegisterUserDto, UpdateAuthDto  } from './dto';

// Entidad
import { User } from './entities/user.entity';

// Bcryptjs
import * as bcryptjs from 'bcryptjs';

// Mongoose
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

// Jwt

import { JwtService } from '@nestjs/jwt';
import { JwTPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';


@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService
  ){}


 async create(createUserDto: CreateUserDto):Promise<User> {  
  
    
    try {
      // 1. Encriptar la contraseña
      const { password, ...userData } = createUserDto; 
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });

      // 2. Guardar el usuario
      await newUser.save();

      const { password:_, ...user } = newUser.toJSON();

      return user;
      
      
      
      // 3. Generar el JWT
      
      
    } catch (error) {
      if (error.code === 11000 ) {
        throw new BadRequestException(`${createUserDto.email} alredy exists!`)
      }
      throw  new InternalServerErrorException('Something terrible happen!!')
    }

  }

  async register( registerDto: RegisterUserDto ):Promise<LoginResponse> {
    
    const user = await this.create( registerDto );
    console.log({ user })

    return {
      user,
      token: this.getJWToken( { id: user._id } ),


    }


  }

 async login(loginDto: LoginDto):Promise<LoginResponse>{

    const { email, password } = loginDto;
    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new UnauthorizedException('Not valid credentials - email ');
    }
    if (!bcryptjs.compareSync( password, user.password )) {
      throw new UnauthorizedException('Not valid - password')
      
    }


    const { password:_, ...userObjFinal } = user.toJSON();
    
    // regresar user y token
    return {
      user: userObjFinal,
      token: this.getJWToken( { id:user.id } ),


    }
  }

  findAll():Promise<User[]> {
    return this.userModel.find()
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

 async findUserById( userId: string ) {

    const user = await  this.userModel.findById(userId);
    const { password, ...rest } = user.toJSON();

    return rest;

  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJWToken( payload:JwTPayload ){
    const token = this.jwtService.sign(payload);
    return token;

  }
}
