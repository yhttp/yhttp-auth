from bddrest import status, response, when, given
from freezegun import freeze_time
import yhttp

from yhttp.ext.auth import install


@freeze_time('2020-01-01')
def test_oauth2_state(app, Given, redis):
    install(app)
    state = None
    app.settings.merge('''
    auth:
      csrf:
        domain: example.com

      oauth2:
        state:
          algorithm: HS256
          secret: quxquux
          maxage: 60  # 1 Minute
          leeway: 10  # seconds
    ''')
    app.ready()

    @app.route('/red')
    def get(req):
        nonlocal state
        state = app.auth.dump_oauth2_state(req, '/foo', dict(bar='baz'))

    @app.route('/blue')
    @yhttp.text
    def get(req, *, state=None):
        state_ = app.auth.verify_oauth2_state(req, state)
        assert state_.bar == 'baz'

    with Given('/red'):
        assert status == 200
        assert state is not None
        cookie = response.headers['Set-Cookie']
        assert cookie.startswith('yhttp-csrf-token=')

    cookie = cookie.split(';')[0]
    with Given(f'/blue?state={state}', headers={'Cookie': cookie}):
        assert status == 200

        when(query=given - 'state')
        assert status == 401

        when(query=given | dict(state='malformed'))
        assert status == 401
