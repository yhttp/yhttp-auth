from bddrest import status, response, when

from yhttp.core import statuscode, text

from yhttp.ext.auth import install, LoginToken, RefreshToken


def test_logintoken_cookie(app, httpreq, redis):
    install(app)
    app.settings.auth.merge('''
    domain: example.com
    logintoken:
      maxage: 30
    refreshtoken:
      maxage: 3600
      path: /tokens
    ''')
    app.ready()

    @app.route('/tokens')
    @statuscode('201 Created')
    def create(req):
        token = LoginToken('Alice')
        app.auth.session_new(req, token)

    @app.route('/tokens')
    @app.auth()
    @statuscode('204 No Content')
    def delete(req):
        app.auth.session_delete(req)

    @app.route('/')
    @app.auth()
    @text
    def whoami(req):
        return f'You are {req.identity.id}'

    with httpreq('/tokens', verb='CREATE'):
        assert status == 201
        assert response.cookies['yhttp-logintoken'].endswith(
            'Domain=example.com; HttpOnly; Max-Age=30; Path=/; '
            'SameSite=Strict'
        )
        assert response.cookies['yhttp-refreshtoken'].endswith(
            'Domain=example.com; HttpOnly; Max-Age=3600; Path=/tokens; '
            'SameSite=Strict'
        )
        logintoken = response.cookies['yhttp-logintoken'].split(';', 1)[0]

    with httpreq('/', verb='WHOAMI'):
        assert status == 401

    with httpreq('/', verb='WHOAMI', cookies={'yhttp-logintoken': logintoken}):
        assert status == 200
        assert response.text == 'You are Alice'

        when('/tokens', verb='DELETE')
        assert status == 204
        assert response.cookies['yhttp-logintoken'] == \
            '""; Domain=example.com; expires=Thu, 01 Jan 1970 00:00:00 GMT; ' \
            'HttpOnly; Path=/; SameSite=Strict'
        assert response.cookies['yhttp-refreshtoken'] == \
            '""; Domain=example.com; expires=Thu, 01 Jan 1970 00:00:00 GMT; ' \
            'HttpOnly; Path=/tokens; SameSite=Strict'
