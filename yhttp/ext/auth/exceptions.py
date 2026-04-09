class AuthException(Exception):
    pass


class TokenDecodeError(AuthException):
    pass


class TokenExpiredError(AuthException):
    pass


class TokenMissmatchError(AuthException):
    pass


class CookieMissingError(AuthException):
    pass


class HeaderMissingError(AuthException):
    pass


class BlacklistError(AuthException):
    pass
