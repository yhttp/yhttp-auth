import pytest

from yhttp.ext.auth import install


def test_authenticator(app):
    install(app)

    with pytest.raises(TypeError):
        app.auth.cookie_token_set(None, 'Invalid Type')

    with pytest.raises(TypeError):
        app.auth.cookie_token_delete(None, 'Invalid Type')
