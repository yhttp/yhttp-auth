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
    @statuscode('201 Created')
    def create(req):
        token = app.auth.dump('foo')
        app.auth.set_cookietoken(req, token)

    @app.route('/tokens')
    @app.auth()
    @text
    @statuscode('204 No Content')
    def delete(req):
        app.auth.delete_cookietoken(req)

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

    with httpreq('/tokens', headers={'Cookie': cookie}, verb='DELETE'):
        assert status == 204
        cookie = response.headers['Set-Cookie']
        assert cookie == \
            'yhttp-token=""; Domain=example.com; ' \
            'expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Path=/; ' \
            'SameSite=Strict; Secure'
