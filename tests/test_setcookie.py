from bddrest import status, response, when

from yhttp.core import statuscode

from yhttp.ext.auth import install


def test_set_cookietoken(app, httpreq):
    install(app)
    app.settings.merge('''
    auth:
    ''')
    app.ready()

    @app.route('/tokens')
    @statuscode('201 created')
    def create(req):
        token = app.auth.dump('foo')
        app.auth.set_cookietoken(req, token)

    with httpreq('/token', verb='CREATE'):
        assert status == 201
        cookie = response.headers['Set-Cookie']
        assert cookie.startswith('yhttp-csrf-token=')
        assert cookie.endswith(
            'Domain=example.com; HttpOnly; Max-Age=60; Path=/red; '
            'SameSite=Strict; Secure'
        )

        when('/blue')
        assert status == 401

        cookie = cookie.split(';')[0]
        when('/blue', headers={'Cookie': cookie})
        assert status == 401

        when(f'/blue?token={token}', headers={'Cookie': cookie})
        assert status == 200

