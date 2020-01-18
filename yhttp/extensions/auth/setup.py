import functools

from .authentication import authenticate
from .cli import JWTCLI


def install(app):
    app.cliarguments.append(JWTCLI)
    app.settings.merge('''
    jwt:
      algorithm: HS256
    ''')

    @app.when
    def ready(app):
        settings = app.settings.jwt
        try:
            settings.secret
        except KeyError:
            raise ValueError(
                'Please provide jwt.secret configuration entry, ' \
                'for example: foobarbaz'
            )

        app.jwt = JWT(settings.secret, settings.algorithm)

    return functools.partial(authenticate, app)

