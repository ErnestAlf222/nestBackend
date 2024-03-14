import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';

// Mongoose
import { MongooseModule } from '@nestjs/mongoose';


@Module({
  imports: [
    ConfigModule.forRoot(),

    // Mongoose
    MongooseModule.forRoot(process.env.MONGO_URI),
    AuthModule
  ],
  controllers: [],
  providers: [],
})
export class AppModule {
  
  
}
