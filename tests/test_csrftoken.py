from bddrest import status, response, when
import yhttp.core as y

from yhttp.ext.auth import install


def test_csrftoken(app, httpreq, redis):
    install(app)
    token = None
    app.settings.auth.merge('''
    csrftoken:
      domain: example.com
    ''')
    app.ready()

    @app.route('/red')
    def get(req):
        nonlocal token
        token = app.auth.csrftoken_create_cookie_set(req)

    @app.route('/blue')
    @y.text
    def get(req, *, token=None):
        app.auth.csrftoken_verify(req, token)

    with httpreq('/red'):
        assert status == 200
        cookie = response.headers['Set-Cookie']
        assert cookie.startswith('yhttp-csrftoken=')
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
