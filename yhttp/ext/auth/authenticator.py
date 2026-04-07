import os
import redis
import hashlib
import functools

from pymlconf import MergableDict

from yhttp.core import statuses

from .token import Token, JWTToken, TokenError, LoginToken, CSRFToken, \
    RefreshToken


class Authenticator:
    defaultsettings = '''
      domain:
      blacklist:
        key: yhttp-auth-forbidden

      redis:
        host: localhost
        port: 6379
        db: 0

      logintoken:
        maxage: 3600     # seconds
        leeway: 10       # seconds
        secret: '12345678901234567890123456789012'
        algorithm: HS256
        cookie:
          key: yhttp-logintoken
          secure: false
          httponly: true
          samesite: Strict
          path: /

      refreshtoken:
        enabled: true
        maxage: 2592000  # 1 Month
        leeway: 10       # seconds
        algorithm: HS256
        secret: '12345678901234567890123456789012'
        cookie:
          key: yhttp-refreshtoken
          secure: false
          httponly: true
          samesite: Strict
          path:

      csrftoken:
        size: 1024
        cookie:
          key: yhttp-csrftoken
          secure: false
          httponly: true
          maxage: 60  # 1 Minute
          samesite: Strict
          path:
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

    def cookie_token_delete(self, req, type_: type):
        if type_ is RefreshToken:
            settings = self._settings.refreshtoken
        elif type_ is LoginToken:
            settings = self._settings.logintoken
        else:
            raise TypeError(f'{type_} is not supported')

        return req.response.setcookie(
            settings.cookie.key,
            '',
            secure=settings.cookie.secure,
            httponly=settings.cookie.httponly,
            domain=self._settings.domain,
            samesite=settings.cookie.samesite,
            path=settings.cookie.path or req.path,
            expires='Thu, 01 Jan 1970 00:00:00 GMT'
        )

    def cookie_token_set(self, req, token: Token):
        if isinstance(token, RefreshToken):
            settings = self._settings.refreshtoken
        elif isinstance(token, LoginToken):
            settings = self._settings.logintoken
        elif isinstance(token, CSRFToken):
            settings = self._settings.csrftoken
        else:
            raise TypeError(f'{type(token)} is not supported')

        if isinstance(token, JWTToken):
            stoken = token.dumps(
                settings.maxage,
                settings.secret,
                settings.algorithm
            )
        else:
            stoken = token.dumps()

        entry = req.response.setcookie(
            settings.cookie.key,
            stoken,
            secure=settings.cookie.secure,
            httponly=settings.cookie.httponly,
            domain=self._settings.domain,
            samesite=settings.cookie.samesite,
            path=settings.cookie.path or req.path,
        )

        if hasattr(settings, 'maxage'):
            entry['max-age'] = settings.maxage

        return entry

    def csrftoken_create(self, size=None):
        size = size or self._settings.csrftoken.size
        return CSRFToken(hashlib.sha256(os.urandom(size)).hexdigest())

    def session_new(self, req, token: LoginToken):
        self.cookie_token_set(req, token)
        if self._settings.refreshtoken.enabled:
            refreshtoken = RefreshToken.create_from_logintoken(token)
            self.cookie_token_set(req, refreshtoken)

    def session_delete(self, req):
        self.cookie_token_delete(req, LoginToken)
        self.cookie_token_delete(req, RefreshToken)

    def session_refresh(self, req):
        pass

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
        except TokenExpiredError:
            raise statuses.unauthorized()

        except TokenError:
            raise statuses.badrequest()

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
                    if not req.identity.authorize(*roles):
                        raise statuses.forbidden()

                return handler(req, *args, **kw)

            return wrapper
        return decorator
