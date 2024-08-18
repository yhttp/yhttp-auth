import pytest
from bddrest import status, response, given, when
from yhttp.core import text, json

from yhttp.ext.auth import install


def test_authorization_token(app, Given, redis):
    auth = install(app)
    app.ready()

    @app.route()
    @auth()
    @text
    def get(req):
        with pytest.raises(AttributeError):
            req.identity.invalidattribute

        return req.identity.id

    @app.route('/admin')
    @auth(roles='admin, god')
    @json
    def get(req):
        return req.identity.roles

    token = app.auth.dump('foo')
    with Given(headers={'Authorization': f'Bearer {token}'}):
        assert status == 200
        assert response.text == 'foo'

        when(headers=given - 'Authorization')
        assert status == 401

        when(headers={'Authorization': 'mAlfoRMeD'})
        assert status == 401

        when(headers={'Authorization': 'Bearer mAlfoRMeD'})
        assert status == 401

    token = app.auth.dump('foo', dict(roles=['admin']))
    with Given('/admin', headers={'Authorization': f'Bearer {token}'}):
        assert status == 200
        assert response.json == ['admin']

        when(headers={'Authorization': token})
        assert status == 401

        app.auth.preventlogin('foo')
        when()
        assert status == 401

        app.auth.permitlogin('foo')
        when()
        assert status == 200

        token = app.auth.dump('foo', dict(roles=['editor']))
        when(headers={'Authorization': f'Bearer {token}'})
        assert status == 403

        token = app.auth.dump('foo')
        when(headers={'Authorization': f'Bearer {token}'})
        assert status == 403
