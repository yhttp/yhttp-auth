import ujson
import jwt


class Identity:
    def __init__(self, payload):
        self.payload = payload

    def __getattr__(self, attr):
        try:
            return self.payload[attr]
        except KeyError:
            raise AttributeError()


class JWT:
    def __init__(self, secret, algorithm='HS256'):
        self.secret = secret
        self.algorithm = algorithm

    def dump(self, payload=None):
        payload = payload or {}
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def verify(self, token):
        return Identity(
            jwt.decode(token, self.secret, algorithms=[self.algorithm])
        )

    def get(self, req):
        return req.headers.get('Authorization')

    def verifyrequest(self, req):
        t = self.get(req)
        return self.verify(t)

