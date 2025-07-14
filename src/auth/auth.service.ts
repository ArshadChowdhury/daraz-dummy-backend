import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import * as speakeasy from 'speakeasy';
import * as crypto from 'crypto';
import { Users } from './entities/users.entity';
import { v4 as uuidv4 } from 'uuid';

// interface User {
//   id: string;
//   email: string;
//   password: string;
//   roles: string[];
//   twoFactorEnabled: boolean;
//   twoFactorSecret?: string;
//   emailVerified: boolean;
//   emailVerificationToken?: string;
//   passwordResetToken?: string;
//   passwordResetExpires?: Date;
//   loginAttempts: number;
//   lockUntil?: Date;
//   createdAt: Date;
//   updatedAt: Date;
// }

interface JwtPayload {
  sub: string;
  email: string;
  roles: string[];
  iat: number;
  exp: number;
  jti: string;
}

@Injectable()
export class AuthService {
  private readonly refreshTokens = new Map<
    string,
    { userId: string; expiresAt: Date; jti: string }
  >();
  private readonly blacklistedTokens = new Set<string>();
  private readonly MAX_LOGIN_ATTEMPTS = 5;
  private readonly LOCK_TIME = 30 * 60 * 1000; // 30 minutes

  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    @InjectRepository(Users)
    private usersRepository: Repository<Users>,
  ) {}

  async register(registerDto: {
    email: string;
    password: string;
    firstName: string;
    lastName?: string;
  }) {
    const { email, password, firstName } = registerDto;

    // // Check if user already exists
    // const existingUser = await this.findUserByEmail(email);
    // if (existingUser) {
    //   throw new ConflictException('User already exists');
    // }

    // Validate password strength
    this.validatePasswordStrength(password);

    // Hash password
    const hashedPassword = await this.hashPassword(password);

    // Create user
    const user = await this.createUser({
      id: uuidv4(),
      email,
      password: hashedPassword,
      roles: ['user'],
      twoFactorEnabled: false,
      emailVerified: false,
      loginAttempts: 0,
    });

    // Generate email verification token
    const verificationToken = this.generateSecureToken();
    // await this.saveEmailVerificationToken(user.id, verificationToken);

    return {
      message: 'User registered successfully',
      userId: user.id,
      verificationToken, // In production, send this via email
    };
  }

  async login(user: any, twoFactorCode?: string) {
    // Handle 2FA if enabled
    if (user.twoFactorEnabled) {
      if (!twoFactorCode) {
        throw new BadRequestException('2FA code required');
      }

      const isValidCode = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: twoFactorCode,
        window: 2,
      });

      if (!isValidCode) {
        throw new UnauthorizedException('Invalid 2FA code');
      }
    }

    // Generate tokens
    return this.generateTokens(user);
  }

  async refreshToken(refreshToken: string) {
    const tokenData = this.refreshTokens.get(refreshToken);

    if (!tokenData || tokenData.expiresAt < new Date()) {
      this.refreshTokens.delete(refreshToken);
      throw new UnauthorizedException('Invalid refresh token');
    }

    const user = await this.findUserById(tokenData.userId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Remove old refresh token
    this.refreshTokens.delete(refreshToken);

    // Blacklist the old JWT
    this.blacklistedTokens.add(tokenData.jti);

    // Generate new tokens
    return this.generateTokens(user);
  }

  async logout(refreshToken: string, jti: string) {
    this.refreshTokens.delete(refreshToken);
    this.blacklistedTokens.add(jti);
    return { message: 'Logged out successfully' };
  }

  async forgotPassword(email: string) {
    const user = await this.findUserByEmail(email);
    if (!user) {
      // Don't reveal if user exists
      return { message: 'If the email exists, a reset link has been sent' };
    }

    const resetToken = this.generateSecureToken();
    const resetExpires = new Date(Date.now() + 3600000); // 1 hour

    await this.savePasswordResetToken(user.id, resetToken, resetExpires);

    return {
      message: 'If the email exists, a reset link has been sent',
      resetToken, // In production, send this via email
    };
  }

  async resetPassword(resetToken: string, newPassword: string) {
    const user = await this.findUserByResetToken(resetToken);
    if (
      !user ||
      !user.passwordResetExpires ||
      user.passwordResetExpires < new Date()
    ) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }

    this.validatePasswordStrength(newPassword);

    const hashedPassword = await this.hashPassword(newPassword);
    await this.updateUserPassword(user.id, hashedPassword);
    await this.clearPasswordResetToken(user.id);

    return { message: 'Password reset successfully' };
  }

  async verifyEmail(token: string) {
    const user = await this.findUserByVerificationToken(token);
    if (!user) {
      throw new UnauthorizedException('Invalid verification token');
    }

    await this.markEmailAsVerified(user.id);
    return { message: 'Email verified successfully' };
  }

  async enable2FA(userId: string) {
    const secret = speakeasy.generateSecret({
      name: 'YourApp',
      account: userId,
      length: 32,
    });

    await this.save2FASecret(userId, secret.base32);

    return {
      secret: secret.base32,
      qrCodeUrl: secret.otpauth_url,
    };
  }

  async verify2FA(userId: string, token: string) {
    const user = await this.findUserById(userId);
    if (!user || !user.twoFactorSecret) {
      throw new BadRequestException('2FA not set up');
    }

    const isValid = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token,
      window: 2,
    });

    if (!isValid) {
      throw new UnauthorizedException('Invalid 2FA code');
    }

    await this.enable2FAForUser(userId);
    return { message: '2FA enabled successfully' };
  }

  async disable2FA(userId: string, token: string) {
    const user = await this.findUserById(userId);
    if (!user || !user.twoFactorEnabled) {
      throw new BadRequestException('2FA not enabled');
    }

    const isValid = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token,
      window: 2,
    });

    if (!isValid) {
      throw new UnauthorizedException('Invalid 2FA code');
    }

    await this.disable2FAForUser(userId);
    return { message: '2FA disabled successfully' };
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ) {
    const user = await this.findUserById(userId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const isCurrentPasswordValid = await bcrypt.compare(
      currentPassword,
      user.password,
    );
    if (!isCurrentPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    this.validatePasswordStrength(newPassword);

    const hashedPassword = await this.hashPassword(newPassword);
    await this.updateUserPassword(userId, hashedPassword);

    return { message: 'Password changed successfully' };
  }

  async validateJwtPayload(payload: JwtPayload): Promise<any> {
    // Check if token is blacklisted
    if (this.blacklistedTokens.has(payload.jti)) {
      throw new UnauthorizedException('Token has been invalidated');
    }

    const user = await this.findUserById(payload.sub);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return {
      userId: payload.sub,
      email: payload.email,
      roles: payload.roles,
      jti: payload.jti,
    };
  }

  // Private helper methods
  private async generateTokens(user: Users) {
    const jti = this.generateJti();
    const payload: Omit<JwtPayload, 'iat' | 'exp'> = {
      sub: user.id,
      email: user.email,
      roles: user.roles,
      jti,
    };

    const accessToken = this.jwtService.sign(payload);
    const refreshToken = this.generateRefreshToken(user.id, jti);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 900, // 15 minutes
      token_type: 'Bearer',
    };
  }

  private generateRefreshToken(userId: string, jti: string): string {
    const token = this.generateSecureToken();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    this.refreshTokens.set(token, { userId, expiresAt, jti });
    return token;
  }

  private generateJti(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  private generateSecureToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  private async hashPassword(password: string): Promise<string> {
    const saltRounds = 12;
    return bcrypt.hash(password, saltRounds);
  }

  private validatePasswordStrength(password: string): void {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length < minLength) {
      throw new BadRequestException(
        'Password must be at least 8 characters long',
      );
    }

    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
      throw new BadRequestException(
        'Password must contain uppercase, lowercase, numbers, and special characters',
      );
    }
  }

  private async handleFailedLogin(userId: string): Promise<void> {
    const user = await this.findUserById(userId);
    if (!user) return;

    const loginAttempts = user.loginAttempts + 1;

    if (loginAttempts >= this.MAX_LOGIN_ATTEMPTS) {
      const lockUntil = new Date(Date.now() + this.LOCK_TIME);
      await this.lockUser(userId, lockUntil);
    } else {
      await this.incrementLoginAttempts(userId, loginAttempts);
    }
  }

  // Database interaction methods (implement based on your ORM/database)
  private async findUserByEmail(email: string): Promise<Users | null> {
    // Implement your database query
    throw new Error('Method not implemented');
  }

  private async findUserById(id: string): Promise<Users | null> {
    // Implement your database query
    throw new Error('Method not implemented');
  }

  private async findUserByResetToken(token: string): Promise<Users | null> {
    // Implement your database query
    throw new Error('Method not implemented');
  }

  private async findUserByVerificationToken(
    token: string,
  ): Promise<Users | null> {
    // Implement your database query
    throw new Error('Method not implemented');
  }

  private async createUser(userData: any): Promise<any> {
    const user: Users = new Users();
    user.email = userData.email;
    user.password = userData.password;

    return this.usersRepository.save(user);
    // Implement your database creation
    // throw new Error('Method not implemented');
  }

  private async updateUserPassword(
    userId: string,
    hashedPassword: string,
  ): Promise<void> {
    // Implement your database update
    throw new Error('Method not implemented');
  }

  private async saveEmailVerificationToken(
    userId: string,
    token: string,
  ): Promise<void> {
    // Implement your database save
    throw new Error('Method not implemented');
  }

  private async savePasswordResetToken(
    userId: string,
    token: string,
    expires: Date,
  ): Promise<void> {
    // Implement your database save
    throw new Error('Method not implemented');
  }

  private async clearPasswordResetToken(userId: string): Promise<void> {
    // Implement your database update
    throw new Error('Method not implemented');
  }

  private async markEmailAsVerified(userId: string): Promise<void> {
    // Implement your database update
    throw new Error('Method not implemented');
  }

  private async save2FASecret(userId: string, secret: string): Promise<void> {
    // Implement your database save
    throw new Error('Method not implemented');
  }

  private async enable2FAForUser(userId: string): Promise<void> {
    // Implement your database update
    throw new Error('Method not implemented');
  }

  private async disable2FAForUser(userId: string): Promise<void> {
    // Implement your database update
    throw new Error('Method not implemented');
  }

  private async resetLoginAttempts(userId: string): Promise<void> {
    // Implement your database update
    throw new Error('Method not implemented');
  }

  private async incrementLoginAttempts(
    userId: string,
    attempts: number,
  ): Promise<void> {
    // Implement your database update
    throw new Error('Method not implemented');
  }

  private async lockUser(userId: string, lockUntil: Date): Promise<void> {
    // Implement your database update
    throw new Error('Method not implemented');
  }
}
