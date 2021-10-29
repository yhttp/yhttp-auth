import jwt
import redis
import functools

from pymlconf import MergableDict
from yhttp import statuses
from yhttp.lazyattribute import lazyattribute


FORBIDDEN_KEY = 'yhttp-auth-forbidden'


class Identity:
    def __init__(self, payload):
        assert payload['id'] is not None
        self.payload = payload

    def __getattr__(self, attr):
        try:
            return self.payload[attr]
        except KeyError:
            raise AttributeError()

    def authorize(self, roles):
        if 'roles' not in self.payload:
            raise statuses.forbidden()

        for r in roles:
            if r in self.roles:
                return r

        raise statuses.forbidden()


class Authenticator:
    redis = None
    default_settings = MergableDict('''
      redis:
        host: localhost
        port: 6379
        db: 0

      token:
        algorithm: HS256
        secret: foobar

      refresh:
        key: yhttp-refresh-token
        algorithm: HS256
        secret: quxquux
        secure: true
        httponly: true
        maxage: 2592000  # 1 Month
        domain:
        path: /

    ''')

    def __init__(self, settings=None):
        self.settings = settings if settings else \
            MergableDict(self.default_settings)
        self.redis = redis.Redis(**self.settings.redis)

    ##########
    # Refresh
    ##########

    @lazyattribute
    def refresh_cookiekey(self):
        return self.settings.refresh.key

    @lazyattribute
    def refresh_secret(self):
        return self.settings.refresh.secret

    @lazyattribute
    def refresh_algorithm(self):
        return self.settings.refresh.algorithm

    def delete_refreshtoken(self, req):
        req.cookies[self.refresh_cookiekey] = ''
        entry = req.cookies[self.refresh_cookiekey]
        entry['Max-Age'] = 0
        entry['Expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'

    def set_refreshtoken(self, req, id, attrs=None):
        settings = self.settings.refresh
        token = self.dump_refreshtoken(id, attrs)

        # Set cookie
        req.cookies[self.refresh_cookiekey] = token
        entry = req.cookies[self.refresh_cookiekey]
        entry['Max-Age'] = settings.maxage

        if settings.secure:
            entry['Secure'] = settings.secure

        if settings.httponly:
            entry['HttpOnly'] = settings.httponly

        if settings.domain:
            entry['Domain'] = settings.domain

        if settings.path:
            entry['Path'] = settings.path
        # TODO: Seems not supported by simple cookie.
        # entry['SameSite'] = 'Strict'
        return entry

    def dump_refreshtoken(self, id, attrs=None):
        payload = {'id': id, 'refresh': True}
        if attrs:
            payload.update(attrs)

        return jwt.encode(payload, self.refresh_secret,
                          algorithm=self.refresh_algorithm)

    def verify_refreshtoken(self, req):
        if self.refresh_cookiekey not in req.cookies:
            raise statuses.unauthorized()

        token = req.cookies[self.refresh_cookiekey].value
        try:
            identity = Identity(jwt.decode(
                token,
                self.refresh_secret,
                algorithms=[self.refresh_algorithm]
            ))

        except (KeyError, jwt.DecodeError):
            raise statuses.unauthorized()

        self.checkstate(identity.id)
        return identity

    #########
    # Token #
    #########

    @lazyattribute
    def secret(self):
        return self.settings.token.secret

    @lazyattribute
    def algorithm(self):
        return self.settings.token.algorithm

    def dump(self, id, attrs=None):
        payload = {'id': id}
        if attrs:
            payload.update(attrs)
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def dump_from_refreshtoken(self, refresh, attrs=None):
        payload = refresh.payload.copy()
        del payload['refresh']

        if attrs:
            payload.update(attrs)
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def checkstate(self, userid):
        if self.redis is not None and \
                self.redis.sismember(FORBIDDEN_KEY, userid):
            raise statuses.unauthorized()

    def decode_token(self, token):
        return jwt.decode(
            token,
            self.secret,
            algorithms=[self.algorithm]
        )

    def verify_token(self, req):
        token = req.headers.get('Authorization')

        if token is None or not token.startswith('Bearer '):
            raise statuses.unauthorized()

        try:
            identity = Identity(self.decode_token(token[7:]))

        except (KeyError, jwt.DecodeError):
            raise statuses.unauthorized()

        self.checkstate(identity.id)
        return identity

    def preventlogin(self, id):
        self.redis.sadd(FORBIDDEN_KEY, id)

    def permitlogin(self, id):
        self.redis.srem(FORBIDDEN_KEY, id)


def authenticate(app, roles=None):
    if isinstance(roles, str):
        roles = [i.strip() for i in roles.split(',')]

    def decorator(handler):
        @functools.wraps(handler)
        def wrapper(req, *args, **kw):
            req.identity = app.auth.verify_token(req)
            if roles is not None:
                req.identity.authorize(roles)

            return handler(req, *args, **kw)

        return wrapper
    return decorator
