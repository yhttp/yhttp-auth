class TokenError(Exception):
    pass


class TokenDecodeError(TokenError):
    pass


class TokenExpiredError(TokenError):
    pass
