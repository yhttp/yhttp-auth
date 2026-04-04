from bddrest import status, response, when, given
import yhttp.core as y

from yhttp.ext.auth import install


def test_oauth2_state(app, httpreq, redis):
    install(app)
    state = None
    app.settings.merge('''
    auth:
      csrf:
        domain: example.com
    ''')
    app.ready()

    @app.route('/red')
    def get(req):
        nonlocal state
        state = app.auth.dump_oauth2_state(req, '/foo', dict(bar='baz'))

    @app.route('/blue')
    @y.text
    def get(req, *, state=None):
        state_ = app.auth.verify_oauth2_state(req, state)
        assert state_.bar == 'baz'
        assert state_.redurl == '/foo'

    with httpreq('/red'):
        assert status == 200
        assert state is not None
        cookie = response.headers['Set-Cookie']
        assert cookie.startswith('yhttp-csrf-token=')
        assert 'Max-Age' in cookie

    cookie = cookie.split(';')[0]
    with httpreq(f'/blue?state={state}', headers={'Cookie': cookie}):
        assert status == 200

        when(query=given - 'state')
        assert status == 401

        when(query=given | dict(state='malformed'))
        assert status == 401
