import { Controller, Get, Post, Body,  UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';

// Dto Transfer
import { CreateUserDto, LoginDto, RegisterUserDto,   } from './dto';

import { AuthGuard } from './guards/auth.guard';
import { User } from './entities/user.entity';
import { LoginResponse } from './interfaces/login-response';

@Controller('auth')
export class AuthController {
  
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createAuthDto: CreateUserDto) {
    
    return this.authService.create(createAuthDto);
  }

  @Post('/login')
  login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Post('/register')
  register(@Body() registerDto: RegisterUserDto) {
    return this.authService.register(registerDto);
  }

  @UseGuards( AuthGuard )
  @Get()
  findAll( @Request()  req: Request  ) {

    // const user = req['user'];
    return this.authService.findAll();
  }

  @UseGuards( AuthGuard)
  @Get('check-token')
  checkToken( @Request() req: Request): LoginResponse{

    const user = req['user'] as User;
    return {
      user,
      token: this.authService.getJWToken({ id: user._id })

    }
  }
  
}
