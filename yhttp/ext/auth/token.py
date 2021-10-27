import jwt
import redis

from yhttp import statuses


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

    def __init__(self, secret, algorithm='HS256', cookiekey='yhttp-token',
                 redisinfo=None):
        self.secret = secret
        self.algorithm = algorithm
        self.cookiekey = cookiekey
        if redisinfo:
            self.redis = redis.Redis(**redisinfo)

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
        return token
