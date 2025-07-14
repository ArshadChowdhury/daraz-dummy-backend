import {
  Controller,
  Post,
  Body,
  UseGuards,
  Request,
  Get,
  Patch,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { Public } from './decorators/public.decorator';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('register')
  async register(
    @Body()
    registerDto: {
      email: string;
      password: string;
      firstName: string;
      lastName?: string;
    },
  ) {
    return this.authService.register(registerDto);
  }

  @Public()
  @Post('login')
  async login(
    @Body()
    loginDto: {
      email: string;
      password: string;
      twoFactorCode?: string;
    },
  ) {
    return this.authService.login(loginDto);
  }

  @Public()
  @Post('refresh')
  async refresh(@Body() refreshDto: { refreshToken: string }) {
    return this.authService.refreshToken(refreshDto.refreshToken);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(@Body() logoutDto: { refreshToken: string }, @Request() req) {
    return this.authService.logout(logoutDto.refreshToken, req.user.jti);
  }

  @Public()
  @Post('forgot-password')
  async forgotPassword(@Body() forgotPasswordDto: { email: string }) {
    return this.authService.forgotPassword(forgotPasswordDto.email);
  }

  @Public()
  @Post('reset-password')
  async resetPassword(
    @Body() resetPasswordDto: { token: string; newPassword: string },
  ) {
    return this.authService.resetPassword(
      resetPasswordDto.token,
      resetPasswordDto.newPassword,
    );
  }

  @Public()
  @Post('verify-email')
  async verifyEmail(@Body() verifyEmailDto: { token: string }) {
    return this.authService.verifyEmail(verifyEmailDto.token);
  }

  @UseGuards(JwtAuthGuard)
  @Post('enable-2fa')
  async enable2FA(@Request() req) {
    return this.authService.enable2FA(req.user.userId);
  }

  @UseGuards(JwtAuthGuard)
  @Post('verify-2fa')
  async verify2FA(@Body() verify2FADto: { token: string }, @Request() req) {
    return this.authService.verify2FA(req.user.userId, verify2FADto.token);
  }

  @UseGuards(JwtAuthGuard)
  @Post('disable-2fa')
  async disable2FA(@Body() disable2FADto: { token: string }, @Request() req) {
    return this.authService.disable2FA(req.user.userId, disable2FADto.token);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('change-password')
  async changePassword(
    @Body() changePasswordDto: { currentPassword: string; newPassword: string },
    @Request() req,
  ) {
    return this.authService.changePassword(
      req.user.userId,
      changePasswordDto.currentPassword,
      changePasswordDto.newPassword,
    );
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async getProfile(@Request() req) {
    return { user: req.user };
  }
}
