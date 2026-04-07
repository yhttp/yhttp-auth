from bddrest import status, response, when
import yhttp.core as y

from yhttp.ext.auth import install


def test_csrftoken(app, httpreq, redis):
    install(app)
    app.settings.auth.merge('''
    domain: example.com
    ''')
    app.ready()
    token = None

    @app.route('/red')
    def get(req):
        nonlocal token
        token = app.auth.csrftoken_create()
        app.auth.cookie_token_set(req, token)

    @app.route('/blue')
    @y.text
    def get(req, *, t=None):
        digest = req.cookies.get('yhttp-csrftoken')
        digest = digest.value if digest else t
        token.assert_(digest)

    with httpreq('/red'):
        assert status == 200
        assert response.cookies['yhttp-csrftoken'].endswith(
            'Domain=example.com; HttpOnly; Path=/red; SameSite=Strict'
        )
        csrftoken = response.cookies['yhttp-csrftoken'].split(';')[0]

        when('/blue')
        assert status == 401

        when('/blue', cookies={'yhttp-csrftoken': csrftoken})
        assert status == 200

        when(f'/blue?t={token.dumps()}')
        assert status == 200
