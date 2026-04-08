import easycli
from bddcli import Given, Application as CLIApplication, status, stderr, \
    stdout, when
from yhttp.core import Application

from yhttp.ext.auth import install


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


def test_jwtcli():
    cliapp = CLIApplication('example', f'{__name__}:app.climain')
    with Given(cliapp, 'auth --help'):
        assert status == 0
        assert stderr == ''

        # Without Payload
        when('auth access-token create foo')
        assert stderr == ''
        assert status == 0
        assert len(stdout.split('.')) == 3

        # With Payload
        when('auth access-token create foo \'{"roles": ["admin"]}\'')
        assert stderr == ''
        assert status == 0
        assert len(stdout.split('.')) == 3

        # Max age
        when('auth access-token create --maxage 10 foo')
        assert stderr == ''
        assert status == 0
        assert len(stdout.split('.')) == 3

        # Without id
        when('auth access-token create')
        assert status == 2
