import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './models/users.model';
import { AuthService } from 'src/auth/auth.service';
import { SignupDTO } from './dto/signup.dto';
import { SigninDTO } from './dto/signin.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
    constructor(
        @InjectModel('User')
        private readonly userModel: Model<User>,
        private readonly authService: AuthService
    ) { }

    public async signup(signupDTO: SignupDTO): Promise<User> {
        const user = new this.userModel(signupDTO);

        return user.save();
    }

    public async signin(signinDTO: SigninDTO): Promise<{
        name: string;
        jwtToken: string;
        email: string;
    }> {
        const user = await this.findByEmail(signinDTO.email);
        const match = await this.checkPassword(signinDTO.password, user);

        if (!match) {
            throw new NotFoundException('Invalid credentials!');
        }

        const jwtToken = await this.authService.createAccessToken(String(user._id));

        return {
            name: user.name,
            jwtToken,
            email: user.email
        };
    }

    public async findAll(): Promise<User[]> {
        return this.userModel.find();
    }

    private async findByEmail(email: string): Promise<User> {
        const userExists = await this.userModel.findOne({
            email
        });

        if (!userExists) {
            throw new NotFoundException('Email not found!');
        }

        return userExists;
    }

    private async checkPassword(password: string, user: User): Promise<boolean> {
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            throw new NotFoundException('Password not found!');
        }

        return match;
    }
}
