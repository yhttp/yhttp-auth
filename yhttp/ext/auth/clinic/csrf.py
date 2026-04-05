from typing import Union

from .token import Token


class CSRFToken(Token):
    def __init__(self, settings, digest: str=None):
        super().__init__(settings)
        self._digest = digest or \
            hashlib.sha256(os.urandom(settings.size)).hexdigest()

    def dumps(self):
        return self._digest

    def verify(self, digest):
        return digest == self._digest

    def assert_(self, digest: Union[str, Request]):
        if isinstance(t, Request):
            digest = req.cookies.get(self._settings.cookie.key)

        if not self.verify(digest):
            raise statuses.unauthorized()


class CSRF:
    defaultsettings = '''
      size: 1024
      cookie:
        key: yhttp-csrftoken
        secure: true
        httponly: true
        maxage: 60  # 1 Minute
        samesite: Strict
        domain:
        path:
    '''


