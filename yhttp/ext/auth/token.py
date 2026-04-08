import abc
from typing import Union
from datetime import datetime, timezone, timedelta

import jwt

from yhttp.core import statuses


class TokenError(Exception):
    pass


class TokenDecodeError(TokenError):
    pass


class TokenExpiredError(TokenError):
    pass


class Token(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def dumps(self):
        raise NotImplementedError()

    def _expirationtime(self, seconds: int):
        return datetime.now(tz=timezone.utc) + timedelta(seconds=seconds)


class CSRFToken(Token):
    def __init__(self, digest: str):
        super().__init__()
        self._digest = digest

    def dumps(self):
        return self._digest

    def verify(self, digest):
        return digest == self._digest

    def assert_(self, digest: str):
        if not self.verify(digest):
            raise statuses.unauthorized()


class JWTToken(Token):
    def __init__(self, payload=None):
        super().__init__()
        self.payload = payload or dict()

    def update(self, payload):
        self.payload.update(payload)

    def dumps(self, maxage, secret, algorithm):
        payload = self.payload.copy()
        payload['exp'] = self._expirationtime(maxage)

        return jwt.encode(
            payload,
            secret,
            algorithm=algorithm
        )

    @classmethod
    def decode(cls, stoken, leeway, algorithm, secret=None) -> dict:
        if secret is None:
            return jwt.decode(
                stoken,
                options={"verify_signature": False},
            )

        try:
            return jwt.decode(
                stoken,
                secret,
                leeway=leeway,
                algorithms=[algorithm]
            )
        except jwt.DecodeError:
            raise TokenDecodeError()

        except jwt.ExpiredSignatureError:
            raise TokenExpiredError()

    @classmethod
    def loads(cls, stoken, leeway, algorithm, secret=None):
        return cls(cls.decode(stoken, leeway, algorith, secret))

    def __getattr__(self, attr):
        try:
            return self.payload[attr]
        except KeyError:
            raise AttributeError()


class AccessToken(JWTToken):
    def __init__(self, id, roles=None, payload=None):
        payload_ = payload.copy() if payload else {}
        payload_['id'] = id
        if not roles:
            roles = ['user']

        payload_['roles'] = roles
        super().__init__(payload_)

    @property
    def roles(self) -> set:
        return set(self._payload['roles'])

    def authorize(self, *roles):
        return set(roles) & self.roles

    @classmethod
    def loads(cls, stoken, leeway, algorithm, secret=None):
        payload = cls.decode(stoken, leeway, algorithm, secret)
        try:
            id = payload.pop('id')
            roles = payload.pop('roles')
        except KeyError:
            raise TokenInvalidError()

        return cls(id, roles, payload)


class RefreshToken(AccessToken):
    @classmethod
    def create_from_accesstoken(cls, accesstoken):
        return cls(accesstoken.id, accesstoken.payload)
