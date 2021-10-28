import pytest
from bddrest import status, response, given, when
from yhttp import text, json

from yhttp.ext.auth import install, JWT


def test_authorization_token(app, Given, redis):
    secret = 'foobarbaz'
    auth = install(app)
    app.settings.merge(f'''
    auth:
      jwt:
        secret: {secret}
    ''')
    token = JWT(app.settings.auth)

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

    with Given(headers={'Authorization': token.dump(dict(id='foo'))}):
        assert status == 200
        assert response.text == 'foo'

        when(headers=given - 'Authorization')
        assert status == 401

        when(headers={'Authorization': 'mAlfoRMeD'})
        assert status == 401

    with Given('/admin', headers={
        'Authorization': token.dump(dict(id='foo', roles=['admin']))
    }):
        assert status == 200
        assert response.json == ['admin']

        app.jwt.preventlogin('foo')
        when()
        assert status == 401

        app.jwt.permitlogin('foo')
        when()
        assert status == 200

        when(headers={
            'Authorization': token.dump(dict(id='foo', roles=['editor']))
        })
        assert status == 403

        when(headers={
            'Authorization': token.dump()
        })
        assert status == 401

        when(headers={
            'Authorization': token.dump(dict(id='foo'))
        })
        assert status == 403


def test_exceptions(app):
    install(app)
    if 'secret' in app.settings.auth.jwt:
        del app.settings.auth.jwt['secret']

    with pytest.raises(ValueError):
        app.ready()


def test_cookie_token(app, Given, redis):
    secret = 'foobarbaz'
    auth = install(app)
    token = None
    app.settings.merge(f'''
    auth:
      jwt:
        secret: {secret}
      cookie:
        token:
          domain: example.com
    ''')

    app.ready()

    @app.route()
    @text
    def login(req):
        nonlocal token
        entry = app.jwt.setcookie(req, dict(id='foo'))
        token = entry.value
        return entry.value

    @app.route()
    @auth()
    @text
    def get(req):
        return req.identity.id

    with Given():
        assert status == 401

        when(verb='LOGIN')
        assert status == 200
        assert response.headers['Set-Cookie'] == \
            f'yhttp-auth={response.text}; ' \
            'Domain=example.com; ' \
            'HttpOnly; Max-Age=2592000; ' \
            'Secure'

    with Given(headers={'Cookie': f'yhttp-auth={token}'}):
        assert status == 200
        assert response.text == 'foo'

        app.jwt.preventlogin('foo')
        when()
        assert status == 401

        app.jwt.permitlogin('foo')
        when()
        assert status == 200
