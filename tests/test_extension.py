import pytest
from bddrest import status, response, given
from yhttp import text

from yhttp.extensions.auth import install, JWT


def test_extension(app, story, when):
    secret = 'foobarbaz'
    token = JWT(secret)
    auth = install(app)
    app.settings.merge(f'''
    jwt:
      secret: {secret}
    ''')

    app.ready()

    @app.route()
    @auth()
    @text
    def get(req):
        with pytest.raises(AttributeError):
            req.identity.invalidattribute

        return req.identity.name

    with story(app, headers={'Authorization': token.dump(dict(name='foo'))}):
        assert status == 200
        assert response.text == 'foo'

        when(headers=given - 'Authorization')
        assert status == 401

        when(headers={'Authorization': 'mAlfoRMeD'})
        assert status == 401


def test_exceptions(app):
    db = install(app)
    if 'secret' in app.settings.jwt:
        del app.settings.jwt['secret']

    with pytest.raises(ValueError):
        app.ready()

