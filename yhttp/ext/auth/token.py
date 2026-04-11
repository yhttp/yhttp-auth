import os
import abc
import hashlib
from datetime import datetime, timezone, timedelta

import jwt

from . import exceptions


class Token(metaclass=abc.ABCMeta):
    pass


class CSRFToken(Token):
    def __init__(self, size: int):
        super().__init__()
        self._digest = hashlib.sha256(os.urandom(size)).hexdigest()

    def dumps(self):
        return self._digest


class JWTToken(Token, metaclass=abc.ABCMeta):
    def __init__(self, **payload):
        self.payload = payload

    def _expirationtime(self, seconds: int):
        return datetime.now(tz=timezone.utc) + timedelta(seconds=seconds)

    def dumps(self, maxage, secret, algorithm):
        payload = self.payload.copy()
        payload['exp'] = self._expirationtime(maxage)

        return jwt.encode(
            payload,
            secret,
            algorithm=algorithm
        )

    def __getattr__(self, name):
        try:
            return self.payload[name]
        except KeyError:
            raise AttributeError(name)

    @classmethod
    def loads(cls, stoken, leeway, algorithm, secret=None,
              verifyexp=True) -> dict:
        try:
            payload = jwt.decode(
                stoken,
                secret,
                leeway=leeway,
                algorithms=[algorithm],
                options={"verify_exp": verifyexp},
            )
        except jwt.DecodeError:
            raise exceptions.TokenDecodeError()

        except jwt.ExpiredSignatureError:
            raise exceptions.TokenExpiredError()

        return cls(**payload)


class AccessToken(JWTToken):
    def __init__(self, id, roles=None, **payload):
        super().__init__(id=id, roles=roles or ['user'], **payload)

    # @property
    # def id(self):
    #     return self.payload['id']

    # @property
    # def roles(self):
    #     return self.payload['roles']

    def authorize(self, *roles):
        return set(roles) & set(self.roles)

    @classmethod
    def create_from(cls, token: 'AccessToken'):
        return cls(**token.payload)


class RefreshToken(AccessToken):
    pass


class OAuth2StateToken(JWTToken):
    def __init__(self, csrf, redirecturl, **payload):
        super().__init__(csrf=csrf, redirecturl=redirecturl, **payload)

    # @property
    # def csrf(self):
    #     return self.payload['csrf']

    # @property
    # def redirecturl(self):
    #     return self.payload['redirecturl']
