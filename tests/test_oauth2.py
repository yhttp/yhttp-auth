from bddrest import status, response, when, given

from yhttp.core import json, statuses

from yhttp.ext.auth import install


def test_oauth2_state(app, httpreq, redis):
    install(app)

    app.settings.auth.merge('''
      domain: example.com
    ''')
    app.ready()

    @app.route('/red')
    @json
    def get(req):
        stoken = app.auth.oauth2_session_new(req, '/foo', dict(bar='baz'))
        raise statuses.found(f'https://oauth2.google.com?state={stoken}')

    # @app.route('/blue')
    # @y.text
    # def get(req, *, stoken=None):
    #     statetoken_ = app.auth.oauth2_statetoken_verify(req, stoken)
    #     assert state_.bar == 'baz'
    #     assert state_.redurl == '/foo'

    with httpreq('/red'):
        assert status == 301
    #     cookie = response.headers['Set-Cookie']
    #     assert cookie.startswith('yhttp-csrftoken=')
    #     assert 'Max-Age' in cookie

    # cookie = cookie.split(';')[0]
    # with httpreq(f'/blue?state={state}', headers={'Cookie': cookie}):
    #     assert status == 200

    #     when(query=given - 'state')
    #     assert status == 401

    #     when(query=given | dict(state='malformed'))
    #     assert status == 401
