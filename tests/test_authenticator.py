import pytest

from yhttp.ext.auth import install


def test_authenticator(app):
    install(app)

    with pytest.raises(TypeError):
        app.auth.tokensettings(type('Invalid Type'))
