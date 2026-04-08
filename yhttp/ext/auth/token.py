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


class BaseToken(metaclass=abc.ABCMeta):
    pass


class CSRFToken(BaseToken):
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


class JWTToken(BaseToken, metaclass=abc.ABCMeta):
    def __init__(self, payload):
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

        return cls(payload)


class AccessToken(JWTToken):
    def __init__(self, id, roles=None, payload=None):
        super().__init__(payload or {})
        self.id = id
        self.roles = roles or ['user']

    @property
    def id(self):
        self.payload['id']

    @id.setter
    def id(self, id):
        self.payload['id'] = id

    @property
    def roles(self):
        self.payload['roles']

    @roles.setter
    def roles(self, roles):
        self.payload['roles'] = roles

    def authorize(self, *roles):
        return set(roles) & set(self.roles)

    @classmethod
    def create_from(cls, token: 'AccessToken'):
        id = token.id
        roles = token.roles
        payload = token.payload.copy()
        return cls(id, roles, payload)


class RefreshToken(AccessToken):
    pass


class OAuth2StateToken(JWTToken):
    def __init__(self, csrf, redirecturl, payload=None):
        super().__init__(payload or {})
        self.csrf = csrf
        self.redirecturl = redirecturl

    @property
    def csrf(self):
        self.payload['csrf']

    @csrf.setter
    def csrf(self, csrf):
        self.payload['csrf'] = csrf

    @property
    def redirecturl(self):
        self.payload['redirecturl']

    @redirecturl.setter
    def redirecturl(self, redirecturl):
        self.payload['redirecturl'] = redirecturl
