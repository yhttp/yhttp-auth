import functools

import bddrest
import pytest
from yhttp.core import Application


@pytest.fixture
def yapp():
    return Application('0.1.0', 'foo')


@pytest.fixture
def Given(yapp):
    return functools.partial(bddrest.Given, yapp)
