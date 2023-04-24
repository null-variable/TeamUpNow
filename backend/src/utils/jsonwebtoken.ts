import { sign, verify } from 'jsonwebtoken';
import { UserToken } from './interfaces';
import { Cache } from 'cache-manager';
import { ConfigService } from '@nestjs/config';

class jsonwebtoken {
  static sign(user: UserToken, configService: ConfigService) {
    const payload = {
      uuid: user.uuid,
      username: user.username,
    };

    return sign(payload, configService.get<string>('SECRET_TOKEN'), {
      expiresIn: '1h',
    });
  }

  static verify(token: string, configService: ConfigService) {
    try {
      const decode = verify(token, configService.get<string>('SECRET_TOKEN')) as UserToken;
      return {
        success: true,
        message: '',
        uuid: decode.uuid,
        username: decode.username,
      };
    } catch (err) {
      return {
        success: false,
        message: err.message,
      };
    }
  }

  static refresh(user: UserToken, configService: ConfigService) {
    return sign({ uuid: user.uuid, username: user.username }, configService.get<string>('SECRET_TOKEN'), {
      algorithm: 'HS256',
      expiresIn: '14d',
    });
  }

  static async refreshVerify(token: string, uuid: string, cache: Cache, configService: ConfigService) {
    try {
      const userCache = await cache.get(uuid);
      if (userCache === token) {
        verify(token, configService.get<string>('SECRET_TOKEN'));
        return true;
      } else {
        return false;
      }
    } catch (err) {
      return false;
    }
  }
}

export default jsonwebtoken;
