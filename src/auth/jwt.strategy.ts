import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(public authService:AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET_KEY,
      algorithms: ['HS256'],
      issuer: 'daraz-dummy-app',
      audience: 'customers-ecommerce',
    });
  }

  async validate(payload: any) {
 // Check if token is blacklisted
  if (this.authService.isTokenBlacklisted(payload.jti)) {
    throw new UnauthorizedException('Token has been revoked');
  }

    // Additional validation logic
    if (payload.exp < Date.now() / 1000) {
      throw new UnauthorizedException('Token expired');
    }

    return {
      userId: payload.sub,
      email: payload.email,
      roles: payload.roles,
      jti: payload.jti,
    };
  }
}
