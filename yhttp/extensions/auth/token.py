#import ujson
import jwt


class JWT:
    def __init__(self, secret, algorithm):
        self.secret = secret
        self.algorithm = algorithm

    def create(self, payload):
        #data = ujson.loads(payload)
        import pudb; pudb.set_trace()  # XXX BREAKPOINT
        data = {}
        return jwt.encode(data, self.secret, algorithm=self.algorithm)

    def verify(self, token):
        return Identity(
            jwt.decode(token, self.secret, algorithms=[self.algorithm])
        )

    def get(self, req):
        return req.headers.get('Authorization')

    def verifyrequest(self, req):
        t = self.get(req)
        return self.verify(t)

