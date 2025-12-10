import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MongooseModule } from '@nestjs/mongoose';
import { UsersSchema } from 'src/users/schemas/users.schema';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './strategies/jwt.strategy';

@Module({
  imports: [MongooseModule.forFeature([
      {
        name: 'User',
        schema: UsersSchema,
      }
    ]), 
    PassportModule, 
    JwtModule.register({
      secret: String(process.env.JWT_SECRET),
      signOptions: {
        expiresIn: Number(process.env.JWT_EXPIRATION)
      },
    })
  ],
  providers: [AuthService, JwtStrategy], 
  exports: [AuthService],
})
export class AuthModule { }
