import functools

from .authentication import Authenticator, authenticate
from .cli import AuthenticatorCLI


def install(app):
    app.cliarguments.append(AuthenticatorCLI)
    app.settings.merge('auth: {}')
    app.settings['auth'].merge(Authenticator.default_settings)

    @app.when
    def ready(app):
        app.auth = Authenticator(app.settings.auth)

    return functools.partial(authenticate, app)
