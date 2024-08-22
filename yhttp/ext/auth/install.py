from .authentication import Authenticator
from .cli import AuthenticatorCLI


def install(app):
    app.cliarguments.append(AuthenticatorCLI)
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
