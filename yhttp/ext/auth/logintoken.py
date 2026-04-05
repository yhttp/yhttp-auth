from .token import JWTToken


class LoginToken(JWTToken):
    def __init__(self, id, roles=None):
        super().__init__(dict(id=id, roles=roles or ['user']))

    def isinroles(self, *roles):
        if 'roles' not in self.payload:
            raise statuses.forbidden()

        for r in roles:
            if r in self.roles:
                return r

        raise statuses.forbidden()

    @classmethod
    def loads(cls, stoken, *args, **kw):
        payload = cls.decode(stoken, *args, **kw)
        id = payload.get('id')

        if not id:
            raise TokenInvalidError()

        del payload['id']
        return cls(id, payload)
