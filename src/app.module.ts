import { Module } from '@nestjs/common';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';

@Module({
  imports: [UsersModule, AuthModule, MongooseModule.forRoot(process.env.MONGO_URI!)],
  controllers: [],
  providers: [],
})
export class AppModule { }
