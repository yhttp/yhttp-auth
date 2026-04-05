from .authentication import Authenticator
from .cli import AuthenticatorCLI


DEFAULT_SETTINGS = '''
  redis:
    host: localhost
    port: 6379
    db: 0

  logintoken:
    algorithm: HS256
    secret: '12345678901234567890123456789012'
    maxage: 3600  # seconds
    leeway: 10  # seconds
    cookie:
      key: yhttp-logintoken
      secure: true
      httponly: true
      domain:
      samesite: Strict
      path: /

  refreshtoken:
    key: yhttp-refreshtoken
    algorithm: HS256
    secret: '12345678901234567890123456789012'
    secure: true
    httponly: true
    maxage: 2592000  # 1 Month
    leeway: 10  # seconds
    domain:
    path:
    samesite: Strict

  csrftoken:
    key: yhttp-csrftoken
    secure: true
    httponly: true
    maxage: 60  # 1 Minute
    samesite: Strict
    domain:
    path:

  oauth2:
    state:
      algorithm: HS256
      secret: '12345678901234567890123456789012'
      maxage: 60  # 1 Minute
      leeway: 10  # seconds

'''


def install(app, cliarguments=None):
    app.cliarguments.append(AuthenticatorCLI)
    if cliarguments:
        AuthenticatorCLI.__arguments__.extend(cliarguments)

    app.settings.merge('auth: {}')
    app.settings.auth.merge(DEFAULT_SETTINGS)
    auth = Authenticator(app.settings.auth)

    @app.when
    def ready(app):
        app.auth.ready()

    @app.when
    def shutdown(app):
        app.auth.shutdown()

    app.auth = auth
