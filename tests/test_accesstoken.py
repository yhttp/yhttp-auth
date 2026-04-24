from bddrest import status, response, when, given
from freezegun import freeze_time

from yhttp.core import text, statuses

from yhttp.ext.auth import install, AccessToken


@freeze_time('2020-01-01 00:00:01')
def test_accesstoken(app, httpreq, redis):
    install(app)
    app.settings.auth.merge('''
    domain: example.com
    accesstoken:
      maxage: 30
      leeway: 4
    refreshtoken:
      enabled: false
    ''')
    app.ready()

    accesstoken_expected = AccessToken('Alice').dumps(
        app.settings.auth.accesstoken.maxage,
        app.settings.auth.accesstoken.secret,
        app.settings.auth.accesstoken.algorithm,
    )

    @app.route('/tokens')
    @statuses.created()
    def create(req):
        token = AccessToken('Alice')
        app.auth.session_new(req, token)

    @app.route('/tokens')
    @app.auth()
    @statuses.nocontent()
    def delete(req):
        app.auth.session_delete(req)

    @app.route('/')
    @app.auth()
    @text
    def whoami(req):
        return f'You are {req.identity.id}'

    @app.route('/admin')
    @app.auth(roles='admin, god', unauthorized='/login.html?then=%s')
    @text
    def get(req):
        return 'Restricted admin area'

    with httpreq(title='Visit protected resource wihtout token',
                 path='/',
                 verb='WHOAMI'):
        assert status == 401

    with httpreq(title='Visit protected resource with malformed token',
                 path='/',
                 verb='WHOAMI',
                 cookies={'yhttp-accesstoken': 'malformed'}):
        assert status == 401

    with httpreq(title='Create a token(aka Login)',
                 path='/tokens',
                 verb='CREATE'):
        assert status == 201
        assert response.cookies['yhttp-accesstoken'] == \
            f'{accesstoken_expected}; ' \
            'Domain=example.com; HttpOnly; Max-Age=34; Path=/; ' \
            'SameSite=Strict'
        assert 'yhttp-refreshtoken' not in response.cookies
        accesstoken = response.cookies['yhttp-accesstoken'].split(';', 1)[0]

    with httpreq(title='Visit protected resource with authorization header',
                 path='/',
                 verb='WHOAMI',
                 headers={'authorization': f'Bearer {accesstoken}'}):
        assert status == 200
        assert response.text == 'You are Alice'

    with httpreq(title='Visit protected resource with cookie access-token',
                 path='/',
                 verb='WHOAMI',
                 cookies={'yhttp-accesstoken': accesstoken}):
        assert status == 200
        assert response.text == 'You are Alice'

        app.auth.blacklist_add('Alice')
        when(title='User is blacklisted')
        assert status == 403
        app.auth.blacklist_remove('Alice')

        when(title='Redirect to login page and preserve url',
             path='/admin',
             verb='GET',
             cookies=given - 'yhttp-accesstoken'
             )
        assert status == 302
        assert response.headers['location'] == '/login.html?then=/admin'

        when(title='Visit unauthorized resource',
             path='/admin',
             verb='GET')
        assert status == 403

        # simulate token expiration
        with freeze_time('2020-01-01 00:01:00'):
            when(title='Visit protected resource with expired token and '
                       'without the refresh token')
            assert status == 401

        when(title='Logout',
             path='/tokens',
             cookies={'yhttp-accesstoken': accesstoken},
             verb='DELETE')
        assert status == 204
        assert response.cookies['yhttp-accesstoken'] == \
            '""; Domain=example.com; expires=Thu, 01 Jan 1970 00:00:00 GMT; ' \
            'HttpOnly; Path=/; SameSite=Strict'

        app.shutdown()
