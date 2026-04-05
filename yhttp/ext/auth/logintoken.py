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
