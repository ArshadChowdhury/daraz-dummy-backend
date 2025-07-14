import { SetMetadata } from '@nestjs/common';

export const Public = () => SetMetadata('isPublic', true);

// decorators/roles.decorator.ts

export const Roles = (...roles: string[]) => SetMetadata('roles', roles);

// .env (add these variables)
// JWT_SECRET_KEY=