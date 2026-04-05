from easycli import SubCommand, Argument
import json


class Create(SubCommand):
    __command__ = 'create'
    __aliases__ = ['c']
    __arguments__ = [
        Argument(
            'id', help='example: alice'
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
            '--maxage', type=int, help='Token maxage in seconds.'
        ),
    ]

    def __call__(self, args):
        app = args.application
        app.ready()

        if args.payload:
            payload = json.loads(args.payload)
        else:
            payload = ''

        token = app.auth.logintoken_create(args.id, args.roles)
        token.update(payload)
        token.maxage = args.maxage
        print(token.dumps())


class Token(SubCommand):
    __command__ = 'token'
    __aliases__ = ['t']
    __arguments__ = [
        Create,
    ]


class AuthenticatorCLI(SubCommand):
    __command__ = 'auth'
    __arguments__ = [
        Token,
    ]
