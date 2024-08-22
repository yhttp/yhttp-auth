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

        print(app.auth.dump(args.id, payload, maxage=args.maxage))


class AuthenticatorCLI(SubCommand):
    __command__ = 'auth'
    __arguments__ = [
        Create,
    ]
