import functools

from .authentication import authenticate
from .cli import JWTCLI
from .token import JWT


def install(app):
    app.cliarguments.append(JWTCLI)
    app.settings.merge('''
    auth:
      redis:
        host: localhost
        port: 6379
        db: 0

      jwt:
        algorithm: HS256

      cookie:
        key: yhttp-auth
    ''')

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

        app.jwt = JWT(
            settings.jwt.secret,
            algorithm=settings.jwt.algorithm,
            cookiekey=settings.cookie.key,
            redisinfo=settings.redis,
        )

    return functools.partial(authenticate, app)
