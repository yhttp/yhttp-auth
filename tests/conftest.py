import functools
from unittest.mock import patch

import bddrest
import pytest

from yhttp import Application


@pytest.fixture
def app():
    return Application()


@pytest.fixture
def Given(app):
    return functools.partial(bddrest.Given, app)


@pytest.fixture
def redis():

    class RedisMock:
        def __init__(self, **kw):
            self.info = kw
            self.maindict = dict()

        def srem(self, key, member):
            set_ = self.maindict.setdefault(key, set())
            if member in set_:
                set_.remove(member)

        def sadd(self, key, member):
            set_ = self.maindict.setdefault(key, set())
            set_.add(member)

        def sismember(self, key, member):
            if key not in self.maindict:
                return False

            return member in self.maindict[key]

        def get(self, key):
            return self.maindict.get(key, '').encode()

        def set(self, key, value):
            self.maindict[key] = value

        def setnx(self, key: str, value):
            if not self.maindict.get(key):
                self.set(key, value)
                return 1
            return 0

        def flushdb(self):
            self.maindict.clear()

    with patch('redis.Redis', new=RedisMock) as p:
        yield p
