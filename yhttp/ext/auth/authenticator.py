import redis
from pymlconf import MergableDict

from .token import Token, JWTToken
from .logintoken import LoginToken


class Authenticator:
    defaultsettings = '''
      redis:
        host: localhost
        port: 6379
        db: 0

      logintoken:
        maxage: 3600  # seconds
        secret: '12345678901234567890123456789012'
        algorithm: HS256
        leeway: 10  # seconds
        cookie:
          key: yhttp-logintoken
          secure: true
          httponly: true
          domain:
          samesite: Strict
          path: /
    '''

    def __init__(self, settings):
        self._settings = settings
        self._redis = None

    def ready(self):
        self._redis = redis.Redis(**self._settings.redis)

    def shutdown(self):
        self._redis.close()

    def cookie_set(self, req, token: Token):
        if isinstance(token, LoginToken):
            settings = self._settings.logintoken
        else:
            raise TypeError(f'{type(token)} is not supported')

        if isinstance(token, JWTToken):
            stoken = token.dumps(
                settings.maxage,
                settings.secret,
                settings.algorithm
            )
        else:
            raise TypeError(f'{type(token)} is not supported')

        entry = req.response.setcookie(settings.cookie.key, stoken)
        if settings.cookie.secure:
            entry['secure'] = settings.cookie.secure

        if settings.cookie.httponly:
            entry['httponly'] = settings.cookie.httponly

        if settings.cookie.domain:
            entry['domain'] = settings.cookie.domain

        if settings.cookie.samesite:
            entry['samesite'] = settings.cookie.samesite

        if settings.maxage:
            entry['max-age'] = settings.maxage

        entry['path'] = settings.cookie.path or req.path
        return entry
