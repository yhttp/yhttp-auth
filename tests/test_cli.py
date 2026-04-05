import easycli
from bddcli import Given, Application as CLIApplication, status, stderr, \
    stdout, when
from freezegun import freeze_time
from yhttp.core import Application

from yhttp.ext.auth import install, AccessToken


class Bar(easycli.SubCommand):
    __command__ = 'bar'

    def __call__(self, args):
        print('bar')


app = Application('0.1.0', 'foo')
authorize = install(app, cliarguments=[Bar])


def test_usercli():
    cliapp = CLIApplication('example', f'{__name__}:app.climain')
    with Given(cliapp, 'auth bar'):
        assert status == 0
        assert stdout == 'bar\n'


def decode(stoken):
    settings = app.settings.auth.accesstoken
    token = AccessToken.loads(
        stoken.strip(),
        settings.leeway,
        settings.algorithm,
        settings.secret
    )
    return token


@freeze_time('2012-02-14 12:00:01+0000')
def test_jwtcli(bddcli_bootpatch):
    cliapp = CLIApplication('example', f'{__name__}:app.climain')
    freezetime = \
        'import freezegun;' \
        'freezegun.freeze_time("2012-02-14 12:00:01+0000").start()\n'

    with bddcli_bootpatch(freezetime), Given(cliapp, 'auth --help'):
        assert status == 0
        assert stderr == ''

        # without Payload
        when('auth access-token create Alice')
        assert stderr == ''
        assert status == 0
        token = decode(stdout)
        assert token.id == 'Alice'
        assert token.roles == ['user']
        assert token.payload['exp'] == 1329224401

        # specify roles
        when('auth access-token create Bob --role admin')
        assert stderr == ''
        assert status == 0
        token = decode(stdout)
        assert token.id == 'Bob'
        assert token.roles == ['user', 'admin']
        assert token.payload['exp'] == 1329224401

        # with Payload
        when('auth access-token create Bob \'{"bar": "baz"}\'')
        assert stderr == ''
        assert status == 0
        token = decode(stdout)
        assert token.id == 'Bob'
        assert token.roles == ['user']
        assert token.payload['bar'] == 'baz'
        assert token.payload['exp'] == 1329224401

        # max age
        when('auth access-token create --maxage 10 Bob')
        assert stderr == ''
        assert status == 0
        token = decode(stdout)
        assert token.id == 'Bob'
        assert token.roles == ['user']
        assert token.payload['exp'] == 1329220811

        # without id
        when('auth access-token create')
        assert status == 2
