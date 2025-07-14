import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET,
      algorithms: ['HS256'],
      issuer: 'your-app-name',
      audience: 'your-app-users',
    });
  }

  async validate(payload: any) {
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
