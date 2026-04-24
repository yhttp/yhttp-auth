from .authenticator import Authenticator
from .cli import AuthenticatorCLI


def install(app, cliarguments=None, **kw):
    app.cliarguments.append(AuthenticatorCLI)
    if cliarguments:
        AuthenticatorCLI.__arguments__.extend(cliarguments)

    app.settings.merge('auth: {}')
    app.settings.auth.merge(Authenticator.defaultsettings)
    auth = Authenticator(app.settings.auth)

    @app.when
    def ready(app):
        app.auth.ready()

    @app.when
    def shutdown(app):
        app.auth.shutdown()

    app.auth = auth
    app.request_factory = auth.middleware(app.request_factory, **kw)
