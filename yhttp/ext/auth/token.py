import abc
from datetime import datetime, timezone, timedelta

import jwt


class TokenError(Exception):
    pass


class TokenDecodeError(TokenError):
    pass


class TokenVerifyError(TokenError):
    pass


class Token(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def dumps(self):
        raise NotImplementedError()

    def _expirationtime(self, seconds: int):
        return datetime.now(tz=timezone.utc) + timedelta(seconds=seconds)


class JWTToken(Token):
    def __init__(self, payload=None):
        super().__init__()
        self._payload = payload or dict()

    def update(self, payload):
        self._payload.update(payload)

    def dumps(self, maxage, secret, algorithm):
        payload = self._payload.copy()
        payload['exp'] = self._expirationtime(maxage)

        return jwt.encode(
            payload,
            secret,
            algorithm=algorithm
        )

    @classmethod
    def decode(cls, stoken, leeway, algorithm, secret=None):
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
            raise TokenVerifyError()

    @classmethod
    def loads(cls, stoken, leeway, algorithm, secret=None):
        if secret is None:
            return cls(jwt.decode(
                stoken,
                options={"verify_signature": False},
            ))

        try:
            return cls(jwt.decode(
                stoken,
                secret,
                leeway=leeway,
                algorithms=[algorithm]
            ))
        except jwt.DecodeError:
            raise TokenDecodeError()

        except jwt.ExpiredSignatureError:
            raise TokenVerifyError()

    def __getattr__(self, attr):
        try:
            return self._payload[attr]
        except KeyError:
            raise AttributeError()
