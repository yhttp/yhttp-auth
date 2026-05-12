from snam import Meld

from .authenticator import Authenticator
from .cli import AuthenticatorCLI


def install(app, cliarguments=None, **kw):
    app.cliarguments.append(AuthenticatorCLI)
    if cliarguments:
        AuthenticatorCLI.__arguments__.extend(cliarguments)

    app.settings |= Meld(Authenticator.defaultsettings, root='auth')
    auth = Authenticator(app.settings.auth)

    @app.when
    def ready(app):
        app.auth.ready()

    @app.when
    def shutdown(app):
        app.auth.shutdown()

    app.auth = auth
    app.request_middlewares.append(auth.request_middleware)
