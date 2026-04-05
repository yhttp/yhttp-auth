from bddrest import status, response, when, given
import yhttp.core as y

from yhttp.ext.auth import install


def test_oauth2_state(app, httpreq, redis):
    install(app)
    state = None
    app.settings.auth.merge('''
    csrftoken:
      domain: example.com
    ''')
    app.ready()

    @app.route('/red')
    def get(req):
        nonlocal state
        state = app.auth.oauth2_state_dump(req, '/foo', dict(bar='baz'))

    @app.route('/blue')
    @y.text
    def get(req, *, state=None):
        state_ = app.auth.oauth2_state_verify(req, state)
        assert state_.bar == 'baz'
        assert state_.redurl == '/foo'

    with httpreq('/red'):
        assert status == 200
        assert state is not None
        cookie = response.headers['Set-Cookie']
        assert cookie.startswith('yhttp-csrftoken=')
        assert 'Max-Age' in cookie

    cookie = cookie.split(';')[0]
    with httpreq(f'/blue?state={state}', headers={'Cookie': cookie}):
        assert status == 200

        when(query=given - 'state')
        assert status == 401

        when(query=given | dict(state='malformed'))
        assert status == 401
