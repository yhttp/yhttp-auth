import redis
import functools

from pymlconf import MergableDict

from yhttp.core import statuses

from .token import Token, JWTToken, TokenError
from .logintoken import LoginToken



class Authenticator:
    defaultsettings = '''
      blacklist:
        key: yhttp-auth-forbidden

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

    def blacklist_has(self, userid):
        # FIXME: use redis hash, hset, hget
        return self._redis.sismember(self._settings.blacklist.key, userid)

    def blacklist_add(self, id):
        self._redis.sadd(self._settings.blacklist.key, id)

    def blacklist_remove(self, id):
        self._redis.srem(self._settings.blacklist.key, id)

    def cookie_set(self, req, key, stoken, secure=None, httponly=None, domain=None,
                   samesite=None, path=None, maxage=None, expires=None):
        entry = req.response.setcookie(key, stoken)
        if secure:
            entry['secure'] = secure

        if httponly:
            entry['httponly'] = httponly

        if domain:
            entry['domain'] = domain

        if samesite:
            entry['samesite'] = samesite

        if path:
            entry['path'] = path

        if maxage:
            entry['max-age'] = maxage

        if expires:
            entry['expires'] = expires

        return entry

    def cookie_token_delete(self, req, type_: type):
        if type_ is LoginToken:
            settings = self._settings.logintoken
        else:
            raise TypeError(f'{type_} is not supported')

        return self.cookie_set(
            req,
            settings.cookie.key,
            '',
            settings.cookie.secure,
            settings.cookie.httponly,
            settings.cookie.domain,
            settings.cookie.samesite,
            settings.cookie.path or req.path,
            None,
            'Thu, 01 Jan 1970 00:00:00 GMT'
        )

    def cookie_token_set(self, req, token: Token):
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

        return self.cookie_set(
            req,
            settings.cookie.key,
            stoken,
            settings.cookie.secure,
            settings.cookie.httponly,
            settings.cookie.domain,
            settings.cookie.samesite,
            settings.cookie.path or req.path,
            settings.maxage,
            None
        )

    def authenticate(self, req):
        settings = self._settings.logintoken
        cookie = req.cookies.get(settings.cookie.key)
        if cookie:
            stoken = cookie.value

        else:
            stoken = req.headers.get('Authorization')
            if stoken is None or not stoken.startswith('Bearer '):
                raise statuses.unauthorized()

            stoken = stoken[7:]

        try:
            identity = LoginToken.loads(
                stoken,
                settings.leeway,
                settings.algorithm,
                settings.secret
            )
        except TokenError:
            raise statuses.unauthorized()

        if self.blacklist_has(identity.id):
            raise statuses.forbidden()

        return identity

    def __call__(self, roles=None):
        if isinstance(roles, str):
            roles = [i.strip() for i in roles.split(',')]

        def decorator(handler):
            @functools.wraps(handler)
            def wrapper(req, *args, **kw):
                req.identity = self.authenticate(req)
                if roles:
                    req.identity.isinroles(*roles)

                return handler(req, *args, **kw)

            return wrapper
        return decorator
