import functools

import bddrest
import pytest
from yhttp.dev.fixtures import redis
from yhttp.core import Application


@pytest.fixture
def app():
    return Application()


@pytest.fixture
def Given(app):
    return functools.partial(bddrest.Given, app)
