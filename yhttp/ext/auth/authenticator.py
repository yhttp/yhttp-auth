import os
import redis
import hashlib
import functools

from pymlconf import MergableDict

from yhttp.core import statuses

from .token import Token, JWTToken, TokenError, LoginToken, CSRFToken


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
          secure: false
          httponly: true
          domain:
          samesite: Strict
          path: /

      csrftoken:
        size: 1024
        cookie:
          key: yhttp-csrftoken
          secure: false
          httponly: true
          maxage: 60  # 1 Minute
          samesite: Strict
          domain:
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

    # def cookie_set(self, req, key, stoken, secure=None, httponly=None, domain=None,
    #                samesite=None, path=None, maxage=None, expires=None):
    #     entry = req.response.setcookie(key, stoken)
    #     if secure:
    #         entry['secure'] = secure

    #     if httponly:
    #         entry['httponly'] = httponly

    #     if domain:
    #         entry['domain'] = domain

    #     if samesite:
    #         entry['samesite'] = samesite

    #     if path:
    #         entry['path'] = path

    #     if maxage:
    #         entry['max-age'] = maxage

    #     if expires:
    #         entry['expires'] = expires

    #     return entry

    def cookie_token_delete(self, req, type_: type):
        if type_ is LoginToken:
            settings = self._settings.logintoken
        else:
            raise TypeError(f'{type_} is not supported')

        return req.response.setcookie(
            settings.cookie.key,
            '',
            secure=settings.cookie.secure,
            httponly=settings.cookie.httponly,
            domain=settings.cookie.domain,
            samesite=settings.cookie.samesite,
            path=settings.cookie.path or req.path,
            expires='Thu, 01 Jan 1970 00:00:00 GMT'
        )

    def cookie_token_set(self, req, token: Token):
        if isinstance(token, LoginToken):
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
            domain=settings.cookie.domain,
            samesite=settings.cookie.samesite,
            path=settings.cookie.path or req.path,
        )

        if hasattr(settings, 'maxage'):
            entry['max-age'] = settings.maxage

        return entry

    def csrftoken_create(self, size=None):
        size = size or self._settings.csrftoken.size
        return CSRFToken(hashlib.sha256(os.urandom(size)).hexdigest())

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
