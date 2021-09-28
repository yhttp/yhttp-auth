import functools


def authenticate(app, roles=None):
    if isinstance(roles, str):
        roles = [i.strip() for i in roles.split(',')]

    def decorator(handler):
        @functools.wraps(handler)
        def wrapper(req, *args, **kw):
            req.identity = app.jwt.verifyrequest(req)
            if roles is not None:
                req.identity.authorize(roles)

            return handler(req, *args, **kw)

        return wrapper
    return decorator
