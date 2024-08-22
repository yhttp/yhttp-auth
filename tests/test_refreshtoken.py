from bddrest import status, response, when
from freezegun import freeze_time
import yhttp.core as y

from yhttp.ext.auth import install


@freeze_time('2020-01-01')
def test_refreshtoken(yapp, Given, redis):
    install(yapp)
    yapp.settings.merge('''
    auth:
      refresh:
        domain: example.com
    ''')
    yapp.ready()

    @yapp.route('/reftokens')
    @y.statuscode(y.statuses.created)
    def create(req):
        yapp.auth.set_refreshtoken(req, 'alice', dict(baz='qux'))

    @yapp.route('/tokens')
    @y.statuscode(y.statuses.created)
    @y.text
    def refresh(req):
        reftoken = yapp.auth.verify_refreshtoken(req)
        return yapp.auth.dump_from_refreshtoken(reftoken, dict(foo='bar'))

    @yapp.route('/tokens')
    @y.json
    def read(req):
        reftoken = yapp.auth.read_refreshtoken(req)
        if reftoken is None:
            return {}
        return reftoken.payload

    @yapp.route('/tokens')
    @yapp.auth()
    @y.text
    def delete(req):
        yapp.auth.delete_refreshtoken(req)

    @yapp.route('/admin')
    @yapp.auth()
    @y.text
    def get(req):
        return req.identity.id

    with Given('/reftokens', verb='CREATE'):
        assert status == 201
        cookie = response.headers['Set-Cookie']
        assert cookie.startswith('yhttp-refresh-token=')
        assert cookie.endswith(
            'Domain=example.com; HttpOnly; Max-Age=2592000; Path=/reftokens; '
            'SameSite=Strict; Secure'
        )

    cookie = cookie.split(';')[0]
    with Given('/tokens', verb='REFRESH'):
        assert status == 401

        when(headers={'Cookie': cookie})
        assert status == 201
        token = response.text
        assert yapp.auth.decode_token(token) == {
            'id': 'alice',
            'baz': 'qux',
            'foo': 'bar',
            'exp': 1577840400,
        }

        with freeze_time('2020-02-01'):
            when(headers={'Cookie': cookie})
            assert status == 401

        when(headers={'Cookie': 'yhttp-refresh-token=Malforrmed'})
        assert status == 401

        when(verb='READ')
        assert status == 200
        assert response.json == {}

        when(headers={'Cookie': 'yhttp-refresh-token=Malformed'}, verb='READ')
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

    with Given('/admin', headers={
        'Authorization': f'Bearer {token}'
    }):
        assert status == 200
        assert response.text == 'alice'

        # One hour + 10 seconds leeway
        with freeze_time('2020-01-01 01:00:11'):
            when()
            assert status == 401

        yapp.auth.preventlogin('alice')
        when()
        assert status == 401

        yapp.auth.permitlogin('alice')
        when()
        assert status == 200

    # Logout
    with Given('/tokens', verb='DELETE'):
        assert status == 401

        when(headers={'Authorization': f'Bearer {token}'})
        assert status == 200
        cookie = response.headers['Set-Cookie']
        assert cookie == \
            'yhttp-refresh-token=""; Domain=example.com; ' \
            'expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Path=/tokens; ' \
            'SameSite=Strict; Secure'
