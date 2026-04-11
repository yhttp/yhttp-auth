import pytest

from yhttp.ext.auth import JWTToken


def test_token():
    token = JWTToken(id='Bob', foo='baz')
    assert token.id == 'Bob'
    assert token.foo == 'baz'
    with pytest.raises(AttributeError):
        token.bar
