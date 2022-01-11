from bddcli import Given, Application as CLIApplication, status, stderr, \
    stdout, when
from yhttp import Application
from yhttp.ext.auth import install


app = Application()
authorize = install(app)


def test_jwtcli():
    cliapp = CLIApplication('example', 'tests.test_cli:app.climain')
    with Given(cliapp, 'auth --help'):
        assert status == 0
        assert stderr == ''

        when('auth create \'{"id": "foo"}\'')
        assert stderr == ''
        assert status == 0
        assert len(stdout.split('.')) == 3

        # Without token
        when('auth create')
        assert stderr == ''
        assert status == 0
        assert len(stdout.split('.')) == 3


if __name__ == '__main__':
    app.climain(['auth', 'c', '{"foo": "bar"}'])
