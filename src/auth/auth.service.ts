import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Request } from 'express';
import { sign } from 'jsonwebtoken';
import { Model } from 'mongoose';
import { User } from 'src/users/models/users.model';
import { JwtPayload } from './models/jwt-payload.model';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel('User')
        private readonly userModel: Model<User>
    ) {}

    public async createAccessToken(userId: string): Promise<string> {
        const secretKey = process.env.JWT_SECRET;
        const expiresToken = Number(process.env.JWT_EXPIRATION);

        if(!secretKey) {
            throw new Error('JWT_SECRET is missing');
        }

        return sign({ userId }, secretKey, {
            expiresIn: expiresToken
        });
    }

    public async validateUser(jwtPayload: JwtPayload): Promise<User>{
        const userExists = await this.userModel.findOne({
            _id: jwtPayload.userId
        });

        if(!userExists){
            throw new NotFoundException('User not found');
        }

        return userExists;
    }

    private jwtExtractor(request: Request): string {
        const authHeader = request.headers.authorization;

        if(!authHeader) {
            throw new BadRequestException('Bad request!');
        }

        const [ type, token ] = authHeader.split(' ');

        return token;
    }

    public returnJwtExtractor(): (request: Request) => string {
        return this.jwtExtractor;
    }
}
