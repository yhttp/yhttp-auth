import pytest
from bddrest import status, response, given, when
from yhttp import text, json

from yhttp.ext.auth import install, JWT


def test_extension(app, Given):
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

    @app.route('/admin')
    @auth(roles='admin, god')
    @json
    def get(req):
        return req.identity.roles

    with Given(headers={'Authorization': token.dump(dict(name='foo'))}):
        assert status == 200
        assert response.text == 'foo'

        when(headers=given - 'Authorization')
        assert status == 401

        when(headers={'Authorization': 'mAlfoRMeD'})
        assert status == 401

    with Given('/admin', headers={
        'Authorization': token.dump(dict(name='foo', roles=['admin']))
    }):
        assert status == 200
        assert response.json == ['admin']

        when(headers={
            'Authorization': token.dump(dict(name='foo', roles=['editor']))
        })
        assert status == 403

        when(headers={
            'Authorization': token.dump()
        })
        assert status == 403


def test_exceptions(app):
    install(app)
    if 'secret' in app.settings.jwt:
        del app.settings.jwt['secret']

    with pytest.raises(ValueError):
        app.ready()
