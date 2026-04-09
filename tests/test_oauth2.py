import os

from bddrest import status, response, when, given
from freezegun import freeze_time

from yhttp.core import json, statuses

from yhttp.ext.auth import install


@freeze_time('2020-01-01 00:00:01')
def test_oauth2_state(app, httpreq, redis, mocker):
    install(app)
    expected_statetoken = \
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjc3JmIjoiZTgzODQzZTdkODgzYz' \
        'E3NjNkYWFhODMyMWRmM2VhNzBiYjViMmM2YzUzZDhlMmVkYmZhZTFiYzJiMjI2YmMxO' \
        'CIsInJlZGlyZWN0dXJsIjoiL2ZvbyIsImJhciI6ImJheiIsImV4cCI6MTU3NzgzNjg2' \
        'MX0.19qb3Cnj8RpIQpCUQuxyzzPixyTZf4syvEHtn0pJM9Q'

    app.settings.auth.merge('''
    domain: example.com
    csrftoken:
      size: 32
    ''')
    app.ready()
    mocker.patch(
        'os.urandom',
        return_value=b'abcdefghijklmnopqrstuvqxyz123456'
    )

    @app.route('/red')
    @json
    def get(req):
        stoken = app.auth.oauth2_session_new(req, '/foo', dict(bar='baz'))
        raise statuses.found(f'https://oauth2.google.com?state={stoken}')

    @app.route('/blue')
    def get(req, *, state=None):
        token = app.auth.oauth2_session_verify(req, state)
        assert token.payload['bar'] == 'baz'
        assert token.redirecturl == '/foo'

    with httpreq('/red'):
        assert status == 302
        assert response.headers['location'] == \
            f'https://oauth2.google.com?state={expected_statetoken}'
        assert response.cookies['yhttp-csrftoken'] == \
            'e83843e7d883c1763daaa8321df3ea70bb5b2c6c53d8e2edbfae1bc2b226bc1' \
            '8; Domain=example.com; HttpOnly; Max-Age=60; Path=/red; ' \
            'SameSite=Strict'
        csrf = response.cookies['yhttp-csrftoken'].split(';', 1)[0]

    with httpreq(
        f'/blue?state={expected_statetoken}',
        cookies={'yhttp-csrftoken': csrf}):
        assert status == 200

    #     when(query=given - 'state')
    #     assert status == 401

    #     when(query=given | dict(state='malformed'))
    #     assert status == 401
