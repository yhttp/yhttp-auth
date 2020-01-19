from easycli import SubCommand, Argument
import json

from .token import JWT



class Create(SubCommand):
    __command__ = 'create'
    __aliases__ = ['c']
    __arguments__ = [
        Argument(
            'payload', default='', nargs='?', help='example: {"foo": "bar"}'
        ),
    ]


    def __call__(self, args):
        settings = args.application.settings.jwt
        jwt = JWT(settings.secret, settings.algorithm)
        print(jwt.dump(json.loads(args.payload)))


class JWTCLI(SubCommand):
    __command__ = 'jwt'
    __arguments__ = [
        Create,
    ]

