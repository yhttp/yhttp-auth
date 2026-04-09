import pytest

from yhttp.ext.auth import install


def test_authenticator_tokensettings(app):
    install(app)

    with pytest.raises(TypeError):
        app.auth.tokensettings(type('Invalid Type'))


# def test_refreshtoken_readepired(app):
#     install(app)
#     app.ready()
#     refreshtoken_expected = RefreshToken('Alice').dumps(
#         app.settings.auth.refreshtoken.maxage,
#         app.settings.auth.refreshtoken.secret,
#         app.settings.auth.refreshtoken.algorithm,
#     )
#
#     with freeze_time('2020-01-01 02:00:00'):
#         with pytest.raises(app.auth.
#     app.shutdown()
#
