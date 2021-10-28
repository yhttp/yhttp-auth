import functools
from unittest.mock import patch

import bddrest
import pytest
from yhttp_devutils.fixtures import redis
from yhttp import Application


@pytest.fixture
def app():
    return Application()


@pytest.fixture
def Given(app):
    return functools.partial(bddrest.Given, app)
