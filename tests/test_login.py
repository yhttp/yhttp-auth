from bddrest import status, response, when
from freezegun import freeze_time

from yhttp.core import statuscode, text

from yhttp.ext.auth import install, LoginToken, RefreshToken


@freeze_time('2020-01-01')
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
        app.auth.cookie_token_set(req, token)
        refreshtoken = RefreshToken.create_from_logintoken(token)
        app.auth.cookie_token_set(req, refreshtoken)

    @app.route('/tokens')
    @app.auth()
    @statuscode('204 No Content')
    def delete(req):
        app.auth.cookie_token_delete(req, type(req.identity))

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
    #     assert response.cookies['yhttp-refreshtoken'] == \
    #         'Domain=example.com; HttpOnly; Max-Age=3600; Path=/tokens; ' \
    #         'SameSite=Strict'

    # with httpreq('/', verb='WHOAMI'):
    #     assert status == 401

    # tokencookie = tokencookie.split(';')[0]
    # with httpreq('/', verb='WHOAMI', headers={'Cookie': tokencookie}):
    #     assert status == 200
    #     assert response.text == 'You are Alice'

    #     when('/tokens', verb='DELETE')
    #     assert status == 204
    #     tokencookie = response.headers['Set-Cookie']
    #     assert tokencookie.startswith('yhttp-logintoken=')
    #     assert tokencookie == 'yhttp-logintoken=""; Domain=example.com; ' \
    #         'expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Path=/; ' \
    #         'SameSite=Strict'
