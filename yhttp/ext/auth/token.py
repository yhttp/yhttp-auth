import jwt
import redis

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


class JWT:
    redis = None
    default_settings = MergableDict('''
      redis:
        host: localhost
        port: 6379
        db: 0

      jwt:
        algorithm: HS256
        secret: foobar

      cookie:
        key: yhttp-auth
        token:
          maxage: 2592000  # 1 Month
          domain:

    ''')

    def __init__(self, settings=None):
        self.settings = settings if settings else \
            MergableDict(self.default_settings)
        self.redis = redis.Redis(**self.settings.redis)

    @lazyattribute
    def secret(self):
        return self.settings.jwt.secret

    @lazyattribute
    def algorithm(self):
        return self.settings.jwt.algorithm

    @lazyattribute
    def cookiekey(self):
        return self.settings.cookie.key

    def dump(self, payload=None):
        payload = payload or {}
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def verify(self, token):
        try:
            identity = Identity(
                jwt.decode(token, self.secret, algorithms=[self.algorithm])
            )

        except (KeyError, jwt.DecodeError):
            raise statuses.unauthorized()

        if self.redis is not None and \
                self.redis.sismember(FORBIDDEN_KEY, identity.id):
            raise statuses.unauthorized()

        return identity

    def get_requesttoken(self, req):
        if self.cookiekey in req.cookies:
            return req.cookies[self.cookiekey].value

        return req.headers.get('Authorization')

    def verifyrequest(self, req):
        token = self.get_requesttoken(req)
        if token is None:
            raise statuses.unauthorized()

        identity = self.verify(token)
        return identity

    def preventlogin(self, id):
        self.redis.sadd(FORBIDDEN_KEY, id)

    def permitlogin(self, id):
        self.redis.srem(FORBIDDEN_KEY, id)

    def setcookie(self, req, payload):
        token = self.dump(payload)
        req.cookies[self.cookiekey] = token
        entry = req.cookies[self.cookiekey]
        entry['Max-Age'] = self.settings.cookie.token.maxage
        entry['Secure'] = True
        entry['HttpOnly'] = True
        entry['Domain'] = self.settings.cookie.token.domain
        # Seems not supported by simple cookie.
        #entry['SameSite'] = 'Strict'
        return entry
