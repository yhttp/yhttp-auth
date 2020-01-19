import ujson
import jwt

from yhttp import statuses


class Identity:
    def __init__(self, payload):
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
    def __init__(self, secret, algorithm='HS256'):
        self.secret = secret
        self.algorithm = algorithm

    def dump(self, payload=None):
        payload = payload or {}
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def verify(self, token):
        try:
            return Identity(
                jwt.decode(token, self.secret, algorithms=[self.algorithm])
            )
        except jwt.DecodeError:
            raise statuses.unauthorized()

    def get(self, req):
        return req.headers.get('Authorization')

    def verifyrequest(self, req):
        t = self.get(req)
        if t is None:
            raise statuses.unauthorized()

        return self.verify(t)

