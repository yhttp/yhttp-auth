from bddrest import status, response, when
from freezegun import freeze_time
import yhttp.core as statuscode, test, statuses

from yhttp.ext.auth import install


@freeze_time('2020-01-01')
def test_refreshtoken(app, httpreq, redis):
    install(app)
    app.settings.auth.refreshtoken.merge('''
    domain: example.com
    ''')
    app.ready()

    @app.route('/reftokens')
    @statuscode(statuses.created)
    def create(req):
        refreshtoken = RefreshToken('Alice', dict(baz='qux'))
        app.auth.cookie_set(req, refreshtoken)

    @app.route('/tokens')
    @statuscode(statuses.created)
    @text
    def refresh(req):
        refreshtoken = app.auth.refreshtoken_verify(req)
        return app.auth.logintoken_dump_from_refreshtoken(
            refreshtoken, dict(foo='bar'))

    @app.route('/tokens')
    @json
    def read(req):
        reftoken = app.auth.refreshtoken_read(req)
        if reftoken is None:
            return {}
        return reftoken.payload

    @app.route('/tokens')
    @app.auth()
    @text
    def delete(req):
        app.auth.refreshtoken_cookie_delete(req)

    @app.route('/admin')
    @app.auth()
    @text
    def get(req):
        return req.identity.id

    with httpreq('/reftokens', verb='CREATE'):
        assert status == 201
        cookie = response.headers['Set-Cookie']
        assert cookie.startswith('yhttp-refreshtoken=')
        assert cookie.endswith(
            'Domain=example.com; HttpOnly; Max-Age=2592000; Path=/reftokens; '
            'SameSite=Strict; Secure'
        )

    cookie = cookie.split(';')[0]
    with httpreq('/tokens', verb='REFRESH'):
        assert status == 401

        when(headers={'Cookie': cookie})
        assert status == 201
        token = response.text
        assert app.auth.logintoken_decode(token) == {
            'id': 'alice',
            'baz': 'qux',
            'foo': 'bar',
            'exp': 1577840400,
        }

        with freeze_time('2020-02-01'):
            when(headers={'Cookie': cookie})
            assert status == 401

        when(headers={'Cookie': 'yhttp-refreshtoken=Malforrmed'})
        assert status == 401

        when(verb='READ')
        assert status == 200
        assert response.json == {}

        when(headers={'Cookie': 'yhttp-refreshtoken=Malformed'}, verb='READ')
        assert status == 200
        assert response.json == {}

        with freeze_time('2020-02-01'):
            when(headers={'Cookie': cookie}, verb='READ')
            assert status == 200
            assert response.json == {
                'baz': 'qux',
                'exp': 1580428800,
                'id': 'alice',
                'refresh': True
            }

    with httpreq('/admin', headers={
        'Authorization': f'Bearer {token}'
    }):
        assert status == 200
        assert response.text == 'alice'

        # One hour + 10 seconds leeway
        with freeze_time('2020-01-01 01:00:11'):
            when()
            assert status == 401

        app.auth.userid_blacklist_set('alice')
        when()
        assert status == 401

        app.auth.userid_blacklist_unset('alice')
        when()
        assert status == 200

    # Logout
    with httpreq('/tokens', verb='DELETE'):
        assert status == 401

        when(headers={'Authorization': f'Bearer {token}'})
        assert status == 200
        cookie = response.headers['Set-Cookie']
        assert cookie == \
            'yhttp-refreshtoken=""; Domain=example.com; ' \
            'expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Path=/tokens; ' \
            'SameSite=Strict; Secure'
