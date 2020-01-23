import functools


def authenticate(app, roles=None):
    def decorator(handler):
        @functools.wraps(handler)
        def wrapper(req, *args, **kw):
            req.identity = app.jwt.verifyrequest(req)

            return handler(req, *args, **kw)

        return wrapper
    return decorator


