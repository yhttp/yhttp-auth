import abc
from datetime import datetime, timezone, timedelta

import jwt


class Token(metaclass=abc.ABCMeta):
    def __init__(self, settings):
        self._settings = settings

    @abc.abstractmethod
    def dumps(self):
        raise NotImplementedError()

    def _expirationtime(self, seconds: int):
        return datetime.now(tz=timezone.utc) + timedelta(seconds=seconds)


class JWTToken(Token):
    def __init__(self, settings, payload=None):
        super().__init__(settings)
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

    def __getattr__(self, attr):
        try:
            return self._payload[attr]
        except KeyError:
            raise AttributeError()
