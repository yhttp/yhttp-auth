from bddrest import status, response, when

from yhttp.core import statuses

from yhttp.ext.auth import install, CSRFToken


def test_csrftoken(app, httpreq, redis, mocker):
    install(app)
    app.settings.auth |= '''
    domain: example.com
    csrftoken:
      size: 32
      cookie:
        path: /red
    '''
    app.ready()
    mocker.patch(
        'os.urandom',
        return_value=b'abcdefghijklmnopqrstuvqxyz123456'
    )
    expected_token = CSRFToken(32).dumps()

    @app.route('/red')
    def get(req):
        token = app.auth.csrftoken_create()
        app.auth.cookie_token_set(req, token)

    @app.route('/blue')
    def get(req, *, t=None):
        digest = req.cookies.get('yhttp-csrftoken')
        digest = digest.value if digest else t
        if expected_token != digest:
            return statuses.forbidden()

    with httpreq('/red'):
        assert status == 200
        assert response.cookies['yhttp-csrftoken'] == \
            f'{expected_token}; Domain=example.com; HttpOnly; Max-Age=60; ' \
            'Path=/red; SameSite=Strict'
        csrftoken = response.cookies['yhttp-csrftoken'].split(';')[0]

        when('/blue')
        assert status == 403

        when('/blue', cookies={'yhttp-csrftoken': csrftoken})
        assert status == 200

        when(f'/blue?t={csrftoken}')
        assert status == 200
