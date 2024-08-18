from bddrest import status, response, when
import yhttp.core as y

from yhttp.ext.auth import install


def test_csrftoken(app, Given, redis):
    install(app)
    token = None
    app.settings.merge('''
    auth:
      csrf:
        domain: example.com
    ''')
    app.ready()

    @app.route('/red')
    def get(req):
        nonlocal token
        token = app.auth.create_csrftoken(req)

    @app.route('/blue')
    @y.text
    def get(req, *, token=None):
        app.auth.verify_csrftoken(req, token)

    with Given('/red'):
        assert status == 200
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
