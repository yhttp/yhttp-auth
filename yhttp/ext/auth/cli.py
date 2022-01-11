from easycli import SubCommand, Argument
import json

from .authentication import Authenticator


class Create(SubCommand):
    __command__ = 'create'
    __aliases__ = ['c']
    __arguments__ = [
        Argument(
            'payload', default='', nargs='?', help='example: {"foo": "bar"}'
        ),
        Argument(
            '--maxage', type=int, help='Token maxage in seconds.'
        ),
    ]

    def __call__(self, args):
        settings = args.application.settings.auth
        jwt = Authenticator(settings)
        if args.payload:
            payload = json.loads(args.payload)
        else:
            payload = ''

        print(jwt.dump(payload, maxage=args.maxage))


class AuthenticatorCLI(SubCommand):
    __command__ = 'auth'
    __arguments__ = [
        Create,
    ]
