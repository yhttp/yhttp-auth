from bddrest import status, response, when
from freezegun import freeze_time

from yhttp.core import statuscode, text

from yhttp.ext.auth import install, AccessToken, RefreshToken


@freeze_time('2020-01-01 00:00:01')
def test_refreshtoken(app, httpreq, redis):
    install(app)
    app.settings.auth.merge('''
    domain: example.com
    accesstoken:
      maxage: 30
    refreshtoken:
      enabled: true
      maxage: 3600
      path: /tokens
    ''')
    app.ready()

    accesstoken_expected = AccessToken('Alice').dumps(
        app.settings.auth.accesstoken.maxage,
        app.settings.auth.accesstoken.secret,
        app.settings.auth.accesstoken.algorithm,
    )
    refreshtoken_expected = RefreshToken('Alice').dumps(
        app.settings.auth.refreshtoken.maxage,
        app.settings.auth.refreshtoken.secret,
        app.settings.auth.refreshtoken.algorithm,
    )

    @app.route('/tokens')
    @statuscode('201 Created')
    def create(req):
        token = AccessToken('Alice')
        app.auth.session_new(req, token)

    @app.route('/tokens')
    @statuscode('201 Created')
    def refresh(req):
        app.auth.session_refresh(req)

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

    with httpreq(title='Create a token(aka Login)',
                 path='/tokens',
                 verb='CREATE'):
        assert status == 201
        assert response.cookies['yhttp-accesstoken'] == \
            f'{accesstoken_expected}; ' \
            'Domain=example.com; HttpOnly; Max-Age=30; Path=/; ' \
            'SameSite=Strict'
        assert response.cookies['yhttp-refreshtoken'] == \
            f'{refreshtoken_expected}; ' \
            'Domain=example.com; HttpOnly; Max-Age=3600; Path=/tokens; ' \
            'SameSite=Strict'
        accesstoken = response.cookies['yhttp-accesstoken'].split(';', 1)[0]
        refreshtoken = response.cookies['yhttp-refreshtoken'].split(';', 1)[0]

    with httpreq(title='Visit protected resource wihtout token',
                 path='/',
                 verb='WHOAMI'):
        assert status == 401

    with httpreq(title='Visit protected resource with token',
                 path='/',
                 verb='WHOAMI',
                 cookies={'yhttp-accesstoken': accesstoken}):
        assert status == 200
        assert response.text == 'You are Alice'

        # simulate token expiration
        when(title='Try to refresh token without any access token',
             path='/tokens',
             verb='REFRESH',
             cookies={
                 'yhttp-refreshtoken': refreshtoken,
             })
        assert status == 401

        when(title='Try to refresh token with access token but without the '
                   'refreshtoken',
             path='/tokens',
             verb='REFRESH',
             cookies={
                 'yhttp-accesstoken': accesstoken,
             })
        assert status == 401

        when(title='Try to refresh token with malformed access token',
             path='/tokens',
             verb='REFRESH',
             cookies={
                 'yhttp-accesstoken': 'malformed-token',
                 'yhttp-refreshtoken': refreshtoken,
             })
        assert status == 401

        when(title='Try to refresh token with malformed refresh token',
             path='/tokens',
             verb='REFRESH',
             cookies={
                 'yhttp-accesstoken': accesstoken,
                 'yhttp-refreshtoken': 'malformed',
             })
        assert status == 401

        bob_refreshtoken = RefreshToken('Bob').dumps(
            app.settings.auth.refreshtoken.maxage,
            app.settings.auth.refreshtoken.secret,
            app.settings.auth.refreshtoken.algorithm,
        )
        when(title='Try to refresh the access-token with Bob\'s refresh token',
             path='/tokens',
             verb='REFRESH',
             cookies={
                 'yhttp-accesstoken': accesstoken,
                 'yhttp-refreshtoken': bob_refreshtoken,
             })
        assert status == 400

        when(title='Try to refresh the access-token',
             path='/tokens',
             verb='REFRESH',
             cookies={
                 'yhttp-accesstoken': accesstoken,
                 'yhttp-refreshtoken': refreshtoken,
             })
        assert status == 201
        assert response.cookies['yhttp-accesstoken'] == \
            f'{accesstoken_expected}; ' \
            'Domain=example.com; HttpOnly; Max-Age=30; Path=/; ' \
            'SameSite=Strict'
        assert response.cookies['yhttp-refreshtoken'] == \
            f'{refreshtoken_expected}; ' \
            'Domain=example.com; HttpOnly; Max-Age=3600; Path=/tokens; ' \
            'SameSite=Strict'
        accesstoken = response.cookies['yhttp-accesstoken'].split(';', 1)[0]

        with freeze_time('2020-01-01 02:00:00'):
            when(title='Try to refresh the access-token when refresh-token is '
                       'expired',
                 path='/tokens',
                 verb='REFRESH',
                 cookies={
                     'yhttp-accesstoken': accesstoken,
                     'yhttp-refreshtoken': refreshtoken,
                 })
            assert status == 401

        when(title='Logout',
             path='/tokens',
             cookies={'yhttp-accesstoken': accesstoken},
             verb='DELETE')
        assert status == 204
        assert response.cookies['yhttp-accesstoken'] == \
            '""; Domain=example.com; expires=Thu, 01 Jan 1970 00:00:00 GMT; ' \
            'HttpOnly; Path=/; SameSite=Strict'
        assert response.cookies['yhttp-refreshtoken'] == \
            '""; Domain=example.com; expires=Thu, 01 Jan 1970 00:00:00 GMT; ' \
            'HttpOnly; Path=/tokens; SameSite=Strict'

        when(title='Visit protected resource after logout',
             cookies={'yhttp-accesstoken': accesstoken})

        # free the time
        app.shutdown()
