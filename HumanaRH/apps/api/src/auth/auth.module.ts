import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { PermissionsGuard } from './guards/permissions.guard';

@Module({
  imports: [
    JwtModule.registerAsync({
      useFactory: () => {
        const secret = process.env.JWT_ACCESS_SECRET;

        if (!secret || Buffer.from(secret).length < 32) {
          throw new Error(
            'JWT_ACCESS_SECRET ausente ou muito curto.',
          );
        }

        return {
          secret,
          signOptions: {
            expiresIn: 900,
          },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtAuthGuard,
    PermissionsGuard,
  ],
  exports: [
    AuthService,
    JwtModule,
    JwtAuthGuard,
    PermissionsGuard,
  ],
})
export class AuthModule {}