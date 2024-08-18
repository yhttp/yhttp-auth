from bddcli import Given, Application as CLIApplication, status, stderr, \
    stdout, when
from yhttp.core import Application

from yhttp.ext.auth import install


app = Application()
authorize = install(app)


def test_jwtcli():
    cliapp = CLIApplication('example', 'tests.test_cli:app.climain')
    with Given(cliapp, 'auth --help'):
        assert status == 0
        assert stderr == ''

        # Without Payload
        when('auth create foo')
        assert stderr == ''
        assert status == 0
        assert len(stdout.split('.')) == 3

        # With Payload
        when('auth create foo \'{"roles": ["admin"]}\'')
        assert stderr == ''
        assert status == 0
        assert len(stdout.split('.')) == 3

        # Max age
        when('auth create --maxage 10 foo')
        assert stderr == ''
        assert status == 0
        assert len(stdout.split('.')) == 3

        # Without id
        when('auth create')
        assert status == 2


if __name__ == '__main__':
    app.climain(['auth', 'c', '{"foo": "bar"}'])
