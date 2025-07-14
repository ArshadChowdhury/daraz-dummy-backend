import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './jwt.strategy';
import { JwtAuthGuard } from './jwt-auth.guard';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { 
        expiresIn: '15m',
        algorithm: 'HS256',
        issuer: 'your-app-name',
        audience: 'your-app-users'
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, JwtAuthGuard],
  exports: [AuthService, JwtAuthGuard],
})
export class AuthModule {}

// auth.service.ts
import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import * as speakeasy from 'speakeasy';

@Injectable()
export class AuthService {
  private readonly refreshTokens = new Map<string, { userId: string; expiresAt: Date }>();

  constructor(private jwtService: JwtService) {}

  async validateUser(email: string, password: string): Promise<any> {
    // Implement your user validation logic
    const user = await this.findUserByEmail(email);
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) throw new UnauthorizedException('Invalid credentials');

    // Check if 2FA is enabled
    if (user.twoFactorEnabled) {
      return { ...user, requires2FA: true };
    }

    return user;
  }

  async login(user: any, twoFactorCode?: string) {
    if (user.requires2FA && user.twoFactorEnabled) {
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

    const payload = { 
      sub: user.id, 
      email: user.email, 
      roles: user.roles,
      iat: Math.floor(Date.now() / 1000),
      jti: this.generateJti()
    };

    const accessToken = this.jwtService.sign(payload);
    const refreshToken = this.generateRefreshToken(user.id);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 900, // 15 minutes
    };
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

    // Generate new tokens
    return this.login(user);
  }

  private generateRefreshToken(userId: string): string {
    const token = this.generateSecureToken();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    
    this.refreshTokens.set(token, { userId, expiresAt });
    return token;
  }

  private generateJti(): string {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  }

  private generateSecureToken(): string {
    return require('crypto').randomBytes(32).toString('hex');
  }

  async logout(refreshToken: string) {
    this.refreshTokens.delete(refreshToken);
  }

  // Implement these methods based on your database
  private async findUserByEmail(email: string): Promise<any> {
    // Your user lookup logic
  }

  private async findUserById(id: string): Promise<any> {
    // Your user lookup logic
  }
}