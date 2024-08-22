from bddrest import status, response, when
import yhttp.core as y

from yhttp.ext.auth import install


def test_csrftoken(yapp, Given, redis):
    install(yapp)
    token = None
    yapp.settings.merge('''
    auth:
      csrf:
        domain: example.com
    ''')
    yapp.ready()

    @yapp.route('/red')
    def get(req):
        nonlocal token
        token = yapp.auth.create_csrftoken(req)

    @yapp.route('/blue')
    @y.text
    def get(req, *, token=None):
        yapp.auth.verify_csrftoken(req, token)

    with Given('/red'):
        assert status == 200
        cookie = response.headers['Set-Cookie']
        assert cookie.startswith('yhttp-csrf-token=')
        assert cookie.endswith(
            'Domain=example.com; HttpOnly; Max-Age=60; Path=/red; '
            'SameSite=Strict; Secure'
        )

        when('/blue')
        assert status == 401

        cookie = cookie.split(';')[0]
        when('/blue', headers={'Cookie': cookie})
        assert status == 401

        when(f'/blue?token={token}', headers={'Cookie': cookie})
        assert status == 200
