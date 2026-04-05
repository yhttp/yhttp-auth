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

    @app.route('/')
    @app.auth()
    @text
    def whoami(req):
        return f'You are {req.identity.id}'

    with httpreq('/tokens', verb='CREATE'):
        assert status == 201
        cookie = response.headers['Set-Cookie']
        assert cookie.startswith('yhttp-logintoken=')
        assert cookie.endswith(
            'Domain=example.com; HttpOnly; Max-Age=30; Path=/; '
            'SameSite=Strict; Secure'
        )

    with httpreq('/', verb='WHOAMI'):
        assert status == 401

        cookie = cookie.split(';')[0]
        when(headers={'Cookie': cookie})
        assert status == 200
        assert response.text == 'You are {foo}'
