from bddrest import status, response, when
import yhttp

from yhttp.ext.auth import install


def test_refreshtoken(app, Given, redis):
    auth = install(app)
    app.settings.merge('''
    auth:
      refresh:
        domain: example.com
    ''')
    app.ready()

    @app.route('/reftokens')
    @yhttp.statuscode(yhttp.statuses.created)
    def create(req):
        app.auth.set_refreshtoken(req, 'alice', dict(baz='qux'))

    @app.route('/tokens')
    @yhttp.statuscode(yhttp.statuses.created)
    @yhttp.text
    def refresh(req):
        reftoken = app.auth.verify_refreshtoken(req)
        return app.auth.dump_from_refreshtoken(reftoken, dict(foo='bar'))

    @app.route('/admin')
    @auth()
    @yhttp.text
    def get(req):
        return req.identity.id

    with Given('/reftokens', verb='CREATE'):
        assert status == 201
        cookie = response.headers['Set-Cookie']
        assert cookie.startswith('yhttp-refresh-token=')
        assert cookie.endswith('HttpOnly; Max-Age=2592000; Secure')

    cookie = cookie.split(';')[0]
    with Given('/tokens', verb='REFRESH'):
        assert status == 401

        when(headers={'Cookie': cookie})
        assert status == 201
        token = response.text
        assert app.auth.decode_token(token) == {
            'id': 'alice',
            'baz': 'qux',
            'foo': 'bar'
        }

        when(headers={'Cookie': 'yhttp-refresh-token=Malforrmed'})
        assert status == 401

    with Given('/admin', headers={
        'Authorization': token
    }):
        assert status == 200
        assert response.text == 'alice'

        app.auth.preventlogin('alice')
        when()
        assert status == 401

        app.auth.permitlogin('alice')
        when()
        assert status == 200