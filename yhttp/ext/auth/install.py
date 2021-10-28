import functools

from .authentication import authenticate
from .cli import JWTCLI
from .token import JWT


def install(app):
    app.cliarguments.append(JWTCLI)
    app.settings.merge('auth: {}')
    app.settings['auth'].merge(JWT.default_settings)

    @app.when
    def ready(app):
        settings = app.settings.auth
        try:
            settings.jwt.secret
        except AttributeError:
            raise ValueError(
                'Please provide jwt.secret configuration entry, '
                'for example: foobarbaz'
            )

        app.jwt = JWT(settings)

    return functools.partial(authenticate, app)
