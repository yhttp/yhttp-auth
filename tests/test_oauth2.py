from bddrest import status, response, when, given
from freezegun import freeze_time

from yhttp.core import json, statuses

from yhttp.ext.auth import install


@freeze_time('2020-01-01 00:00:01')
def test_oauth2_state(app, httpreq, redis):
    install(app)
    expected_statetoken = \
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJiYXIiOiJiYXoiLCJjc3JmIjoiMD' \
        'c5OWRmZTE3NjMyZjlhYzBjNGUzNmQwZDUwODIyNzMzM2MxNTUzZDYyOGFmYTVjOGFhZ' \
        'mYwZGYwMGJiMTg3NiIsInJlZGlyZWN0dXJsIjoiL2ZvbyIsImV4cCI6MTU3NzgzNjg2' \
        'MX0.Yla2vkUMLUhmnUbtyDY_puv3OsrXEUUKNow1wtq9o-A'

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
        assert status == 302
        assert response.headers['location'] == \
            f'https://oauth2.google.com?state={expected_statetoken}'
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
