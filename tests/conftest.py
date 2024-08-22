import functools

import bddrest
import pytest
from yhttp.dev.fixtures import redis
from yhttp.core import Application


@pytest.fixture
def yapp():
    return Application()


@pytest.fixture
def Given(yapp):
    return functools.partial(bddrest.Given, yapp)
