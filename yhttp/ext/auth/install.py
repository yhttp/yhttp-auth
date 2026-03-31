from .authentication import Authenticator
from .cli import AuthenticatorCLI


def install(app, cliarguments=None):
    app.cliarguments.append(AuthenticatorCLI)
    if cliarguments:
        AuthenticatorCLI.__arguments__.extend(cliarguments)

    app.settings.merge('auth: {}')
    app.settings['auth'].merge(Authenticator.default_settings)

    auth = Authenticator()

    @app.when
    def ready(app):
        app.auth.open(app.settings.auth)

    @app.when
    def shutdown(app):
        app.auth.close()

    app.auth = auth
