import redis
import functools

from yhttp.core import statuses

from .exceptions import TokenExpiredError, TokenDecodeError, \
    TokenMissingError, BlacklistError, TokenMissmatchError
from .token import Token, JWTToken, AccessToken, CSRFToken, RefreshToken, \
    OAuth2StateToken


class Authenticator:
    defaultsettings = '''
      domain:
      blacklist:
        key: yhttp-auth-forbidden

      redis:
        host: localhost
        port: 6379
        db: 0

      accesstoken:
        maxage: 3600     # seconds
        leeway: 10       # seconds
        secret: '12345678901234567890123456789012'
        algorithm: HS256
        cookie:
          key: yhttp-accesstoken
          secure: false
          httponly: true
          samesite: Strict
          path: /

      refreshtoken:
        enabled: false
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

      oauth2:
        statetoken:
          algorithm: HS256
          secret: '12345678901234567890123456789012'
          maxage: 60   # 1 Minute
          leeway: 10   # seconds
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

    def cookie_token_delete(self, req, tokentype: type):
        settings = self.tokensettings(tokentype)

        return req.response.setcookie(
            settings.cookie.key,
            '',
            secure=settings.cookie.secure,
            httponly=settings.cookie.httponly,
            domain=self._settings.domain,
            samesite=settings.cookie.samesite,
            path=settings.cookie.path,
            expires='Thu, 01 Jan 1970 00:00:00 GMT'
        )

    def tokensettings(self, tokentype: type):
        if tokentype is OAuth2StateToken:
            return self._settings.oauth2.statetoken

        if tokentype is RefreshToken:
            return self._settings.refreshtoken

        if tokentype is AccessToken:
            return self._settings.accesstoken

        if tokentype is CSRFToken:
            return self._settings.csrftoken

        raise TypeError(f'{tokentype} is not supported')

    def token_dumps(self, token: Token):
        settings = self.tokensettings(type(token))
        if isinstance(token, JWTToken):
            stoken = token.dumps(
                settings.maxage,
                settings.secret,
                settings.algorithm
            )
        else:
            stoken = token.dumps()

        return stoken

    def cookie_token_set(self, req, token: Token):
        settings = self.tokensettings(type(token))
        stoken = self.token_dumps(token)
        entry = req.response.setcookie(
            settings.cookie.key,
            stoken,
            secure=settings.cookie.secure,
            httponly=settings.cookie.httponly,
            domain=self._settings.domain,
            samesite=settings.cookie.samesite,
            path=settings.cookie.path,
        )

        if hasattr(settings, 'maxage'):
            entry['max-age'] = settings.maxage + settings.leeway
        elif hasattr(settings.cookie, 'maxage'):
            entry['max-age'] = settings.cookie.maxage

        return entry

    def csrftoken_create(self, size=None):
        size = size or self._settings.csrftoken.size
        return CSRFToken(size)

    def session_new(self, req, token: AccessToken):
        self.cookie_token_set(req, token)
        if self._settings.refreshtoken.enabled:
            refreshtoken = RefreshToken.create_from(token)
            self.cookie_token_set(req, refreshtoken)

    def session_delete(self, req):
        self.cookie_token_delete(req, AccessToken)
        self.cookie_token_delete(req, RefreshToken)

    def token_loads(self, stoken: str, type_: Token, verifyexp=True):
        settings = self.tokensettings(type_)
        token = type_.loads(
            stoken,
            settings.leeway,
            settings.algorithm,
            settings.secret,
            verifyexp=verifyexp,
        )
        return token

    def token_fromcookie(self, req, type_: type, verifyexp=True):
        settings = self.tokensettings(type_)
        cookie = req.cookies.get(settings.cookie.key)
        if not cookie or not cookie.value:
            raise TokenMissingError()

        return self.token_loads(
            cookie.value,
            type_,
            verifyexp=verifyexp,
        )

    def session_refresh(self, req):
        refreshtoken = self.token_fromcookie(
            req,
            RefreshToken
        )

        accesstoken = AccessToken.create_from(refreshtoken)
        self.session_new(req, accesstoken)

    def oauth2_session_new(self, req, redirecturl, payload) -> str:
        # generate a new csrf token and store into cookie
        csrftoken = self.csrftoken_create()
        scsrf = self.token_dumps(csrftoken)
        self.cookie_token_set(req, csrftoken)

        # generate an state token containing csrf and other info
        statetoken = OAuth2StateToken(scsrf, redirecturl, **payload)
        return self.token_dumps(statetoken)

    def oauth2_session_verify(self, req, sstatetoken: str):
        clientcsrf = req.cookies.get('yhttp-csrftoken')
        if not clientcsrf or not clientcsrf.value:
            raise TokenMissingError()

        token = self.token_loads(
            sstatetoken,
            OAuth2StateToken
        )

        if token.csrf != clientcsrf.value:
            raise TokenMissmatchError()

        return token

    def authenticate(self, req):
        settings = self._settings.accesstoken
        cookie = req.cookies.get(settings.cookie.key)
        if cookie:
            stoken = cookie.value

        else:
            stoken = req.headers.get('Authorization')
            if stoken is None or not stoken.startswith('Bearer '):
                raise TokenMissingError()

            stoken = stoken[7:]

        accesstoken = self.token_loads(stoken, AccessToken)

        if self.blacklist_has(accesstoken.id):
            raise BlacklistError()

        return accesstoken

    def middleware(self, request_factory, unauthorized=statuses.unauthorized,
                   forbidden=statuses.forbidden):

        @functools.wraps(request_factory)
        def factory(app, environ, response):
            req = request_factory(app, environ, response)
            try:
                req.identity = self.authenticate(req)
            except (TokenExpiredError, TokenMissingError):
                req.identity = None

            except TokenDecodeError:
                self.cookie_token_delete(req, AccessToken)
                raise unauthorized()

            except BlacklistError:
                raise forbidden()

            return req

        return factory

    def __call__(self, roles=None, unauthorized=statuses.unauthorized,
                 forbidden=statuses.forbidden):
        if isinstance(roles, str):
            roles = [i.strip() for i in roles.split(',')]

        def decorator(handler):
            @functools.wraps(handler)
            def wrapper(req, *args, **kw):
                if req.identity is None:
                    if isinstance(unauthorized, str):
                        raise statuses.found(unauthorized % req.path)

                    raise unauthorized()

                if roles:
                    if not req.identity.authorize(*roles):
                        raise forbidden()

                return handler(req, *args, **kw)

            return wrapper
        return decorator
