from easycli import SubCommand, Argument
import json


class AccessTokenCreate(SubCommand):
    __command__ = 'create'
    __aliases__ = ['c']
    __arguments__ = [
        Argument(
            'id', help='example: alice',
        ),
        Argument(
            '--role',
            default=['user'],
            dest='roles',
            action='append',
            help='User role, can be specified multiple times. default: `user`.'
        ),
        Argument(
            'payload', default='', nargs='?', help='example: {"foo": "bar"}'
        ),
        Argument(
            '--maxage', default=None, type=int, help='Token maxage in seconds.'
        ),
    ]

    def __call__(self, args):
        from yhttp.ext.auth import AccessToken

        app = args.application
        app.ready()

        if args.payload:
            payload = json.loads(args.payload)
        else:
            payload = {}

        token = AccessToken(args.id, args.roles, **payload)
        settings = app.auth.tokensettings(type(token))
        stoken = token.dumps(
            args.maxage or settings.maxage,
            settings.secret,
            settings.algorithm
        )
        print(stoken)


class AccessTokenCommand(SubCommand):
    __command__ = 'access-token'
    __aliases__ = ['t']
    __arguments__ = [
        AccessTokenCreate,
    ]


class AuthenticatorCLI(SubCommand):
    __command__ = 'auth'
    __arguments__ = [
        AccessTokenCommand,
    ]
