from bddcli import Given, Application as CLIApplication, status, stderr, \
    stdout, when
from yhttp import Application
from yhttp.extensions.auth import install


app = Application()
app.settings.merge('''
jwt:
  secret: foobarbaz
''')
authorize = install(app)


def test_jwtcli():
    cliapp = CLIApplication('example', 'tests.test_cli:app.climain')
    with Given(cliapp, 'jwt --help'):
        assert status == 0
        assert stderr == ''

        when('jwt create \'{"foo": "bar"}\'')
        print(stderr)
        assert status == 0
        assert len(stdout.split('.')) == 3


if __name__ == '__main__':
    app.climain(['jwt', 'c', '{"foo": "bar"}'])
