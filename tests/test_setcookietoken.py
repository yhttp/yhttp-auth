from bddrest import status, response, when

from yhttp.core import statuscode, text

from yhttp.ext.auth import install


def test_set_cookietoken(app, httpreq):
    install(app)
    app.settings.merge('''
    auth:
      token:
        maxage: 30
        cookie:
          domain: example.com
    ''')
    app.ready()

    @app.route('/tokens')
    @statuscode('201 created')
    def create(req):
        token = app.auth.dump('foo')
        app.auth.set_cookietoken(req, token)

    @app.route('/foo')
    @app.auth()
    @text
    def get(req):
        return 'Foo'

    with httpreq('/tokens', verb='CREATE'):
        assert status == 201
        cookie = response.headers['Set-Cookie']
        assert cookie.startswith('yhttp-token=')
        assert cookie.endswith(
            'Domain=example.com; HttpOnly; Max-Age=30; Path=/; '
            'SameSite=Strict; Secure'
        )

    with httpreq('/foo'):
        assert status == 401

        cookie = cookie.split(';')[0]
        when(headers={'Cookie': cookie})
        assert status == 200
