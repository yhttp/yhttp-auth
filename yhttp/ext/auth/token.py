import abc
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


class AccessToken(Token):
    def __init__(self, id, roles=None, payload=None):
        self.id = id
        self.roles = roles or ['user']
        self.payload = payload or {}

    def authorize(self, *roles):
        return set(roles) & set(self.roles)

    def _expirationtime(self, seconds: int):
        return datetime.now(tz=timezone.utc) + timedelta(seconds=seconds)

    def dumps(self, maxage, secret, algorithm):
        payload = self.payload.copy()
        payload['exp'] = self._expirationtime(maxage)
        payload['id'] = self.id
        payload['roles'] = self.roles

        return jwt.encode(
            payload,
            secret,
            algorithm=algorithm
        )

    @classmethod
    def loads(cls, stoken, leeway, algorithm, secret=None) -> dict:
        try:
            if secret:
                payload = jwt.decode(
                    stoken,
                    secret,
                    leeway=leeway,
                    algorithms=[algorithm]
                )
            else:
                payload = jwt.decode(
                    stoken,
                    options={"verify_signature": False},
                )
        except jwt.DecodeError:
            raise TokenDecodeError()

        except jwt.ExpiredSignatureError:
            raise TokenExpiredError()

        return cls(payload.pop('id'), payload.pop('roles'), payload)

    @classmethod
    def create_from_refreshtoken(cls, refreshtoken):
        id = refreshtoken.id
        roles = refreshtoken.roles
        payload = refreshtoken.payload.copy()
        return cls(id, roles, payload)


class RefreshToken(AccessToken):
    @classmethod
    def create_from_accesstoken(cls, accesstoken):
        id = accesstoken.id
        roles = accesstoken.roles
        payload = accesstoken.payload.copy()
        return cls(id, roles, payload)
