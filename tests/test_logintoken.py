from bddrest import status, response, when

from yhttp.core import statuscode, text

from yhttp.ext.auth import install, LoginToken


def test_logintoken(app, httpreq, redis):
    install(app)
    app.settings.auth.logintoken.merge('''
    maxage: 30
    cookie:
      domain: example.com
    ''')
    app.ready()

    @app.route('/tokens')
    @statuscode('201 Created')
    def create(req):
        token = LoginToken('foo')
        app.auth.cookie_set(req, token)

    with httpreq('/tokens', verb='CREATE'):
        assert status == 201
        cookie = response.headers['Set-Cookie']
        assert cookie.startswith('yhttp-logintoken=')
        assert cookie.endswith(
            'Domain=example.com; HttpOnly; Max-Age=30; Path=/; '
            'SameSite=Strict; Secure'
        )
