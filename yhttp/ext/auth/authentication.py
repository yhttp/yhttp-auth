import os
import jwt
import hashlib
import functools
from datetime import datetime, timedelta, timezone

import redis
from yhttp.core import statuses


FORBIDDEN_REDIS_KEY = 'yhttp-auth-forbidden'


# encapsulate all tokens inside this class with dumps and loads method
class Token:
    def __init__(self, payload):
        assert payload['id'] is not None
        self.payload = payload

    def __getattr__(self, attr):
        try:
            return self.payload[attr]
        except KeyError:
            raise AttributeError()

    def authorize(self, *roles):
        if 'roles' not in self.payload:
            raise statuses.forbidden()

        for r in roles:
            if r in self.roles:
                return r

        raise statuses.forbidden()


class Authenticator:
    redis = None

    def __init__(self, settings):
        self.settings = settings

    def ready(self):
        self.redis = redis.Redis(**self.settings.redis)

    def shutdown(self):
        self.redis.close()

    def _calculate_expirationtime(self, seconds):
        return datetime.now(tz=timezone.utc) + timedelta(seconds=seconds)

    ##########
    # OAuth2 #
    ##########

    def oauth2_state_dump(self, req, redirect_url, attrs=None):
        settings = self.settings.oauth2.state
        payload = {
            'exp': self._calculate_expirationtime(settings.maxage),
            'redurl': redirect_url,
            'id': self.csrftoken_create_cookie_set(req)
        }
        if attrs:
            payload.update(attrs)

        return jwt.encode(
            payload,
            settings.secret,
            algorithm=settings.algorithm
        )

    def oauth2_state_decode(self, state):
        settings = self.settings.oauth2.state
        return jwt.decode(
            state,
            settings.secret,
            leeway=settings.leeway,
            algorithms=[settings.algorithm]
        )

    def oauth2_state_verify(self, req, state):
        if state is None:
            raise statuses.unauthorized()

        try:
            identity = Token(self.oauth2_state_decode(state))
        except (KeyError, jwt.DecodeError, jwt.ExpiredSignatureError):
            raise statuses.unauthorized()

        self.csrftoken_verify(req, identity.id)
        return identity

    ########
    # CSRF #
    ########

    def csrftoken_cookie_set(self, req, csrftoken):
        settings = self.settings.csrftoken

        # Set cookie
        entry = req.response.setcookie(settings.key, csrftoken)

        if settings.secure:
            entry['secure'] = settings.secure

        if settings.httponly:
            entry['httponly'] = settings.httponly

        if settings.domain:
            entry['domain'] = settings.domain

        if settings.samesite:
            entry['samesite'] = settings.samesite

        if settings.maxage:
            entry['max-age'] = settings.maxage

        entry['path'] = settings.path if settings.path else req.path
        return entry

    def csrftoken_create_cookie_set(self, req):
        # Create a state csrftoken to prevent request forgery.
        csrftoken = hashlib.sha256(os.urandom(1024)).hexdigest()

        self.csrftoken_cookie_set(req, csrftoken)
        return csrftoken

    def csrftoken_verify(self, req, csrftoken):
        settings = self.settings.csrftoken
        ctoken = req.cookies.get(settings.key)
        if ctoken is None:
            raise statuses.unauthorized()

        if ctoken.value != csrftoken:
            raise statuses.unauthorized()

    #################
    # Refresh Token #
    #################

    def refreshtoken_cookie_set(self, req, refreshtoken):
        settings = self.settings.refreshtoken

        # Set cookie
        entry = req.response.setcookie(settings.key, refreshtoken)

        if settings.secure:
            entry['secure'] = settings.secure

        if settings.httponly:
            entry['httponly'] = settings.httponly

        if settings.domain:
            entry['domain'] = settings.domain

        if settings.samesite:
            entry['samesite'] = settings.samesite

        entry['path'] = settings.path if settings.path else req.path
        return entry

    def refreshtoken_cookie_delete(self, req):
        entry = self.refreshtoken_cookie_set(req, '')
        entry['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
        return entry

    def refreshtoken_cookie_create_set(self, req, id, attrs=None):
        settings = self.settings.refreshtoken
        refreshtoken = self.refreshtoken_dump(id, attrs)

        # Set cookie
        entry = self.refreshtoken_cookie_set(req, refreshtoken)
        entry['max-age'] = settings.maxage
        return entry

    # TODO: remove it
    def refreshtoken_dump(self, id, attrs=None):
        settings = self.settings.refreshtoken
        payload = {
            'id': id,
            'refresh': True,
            'exp': self._calculate_expirationtime(settings.maxage)
        }
        if attrs:
            payload.update(attrs)

        return jwt.encode(
            payload,
            settings.secret,
            algorithm=settings.algorithm
        )

    def refreshtoken_verify(self, req):
        settings = self.settings.refreshtoken
        if settings.key not in req.cookies:
            raise statuses.unauthorized()

        refreshtoken = req.cookies[settings.key].value
        try:
            identity = Token(jwt.decode(
                refreshtoken,
                settings.secret,
                leeway=settings.leeway,
                algorithms=[settings.algorithm]
            ))

        except (KeyError, jwt.DecodeError, jwt.ExpiredSignatureError):
            raise statuses.unauthorized()

        self.userid_blacklist_check(identity.id)
        return identity

    def refreshtoken_read(self, req):
        settings = self.settings.refreshtoken
        if settings.key not in req.cookies:
            return None

        refreshtoken = req.cookies[settings.key].value
        try:
            identity = Token(jwt.decode(
                refreshtoken,
                options={"verify_signature": False},
            ))

        except (KeyError, jwt.DecodeError):
            return None

        return identity

    #########
    # Token #
    #########

    def logintoken_dump(self, id, attrs=None, maxage=None):
        settings = self.settings.logintoken
        payload = {
            'id': id,
            'exp': self._calculate_expirationtime(maxage or settings.maxage)
        }
        if attrs:
            payload.update(attrs)

        return jwt.encode(
            payload,
            settings.secret,
            algorithm=settings.algorithm
        )

    def logintoken_dump_from_refreshtoken(self, refresh, attrs=None):
        settings = self.settings.logintoken
        payload = refresh.payload.copy()
        del payload['refresh']

        if attrs:
            payload.update(attrs)

        payload['exp'] = self._calculate_expirationtime(settings.maxage)
        return jwt.encode(
            payload,
            settings.secret,
            algorithm=settings.algorithm
        )

    # TODO: remove this
    def logintoken_decode(self, token):
        settings = self.settings.logintoken
        return jwt.decode(
            token,
            settings.secret,
            leeway=settings.leeway,
            algorithms=[settings.algorithm]
        )

    def logintoken_verify(self, req):
        settings = self.settings.logintoken
        token = req.cookies.get(settings.cookie.key)
        if token:
            token = token.value

        else:
            token = req.headers.get('Authorization')
            if token is None or not token.startswith('Bearer '):
                raise statuses.unauthorized()

            token = token[7:]

        try:
            identity = Token(self.logintoken_decode(token))
        except (KeyError, jwt.DecodeError, jwt.ExpiredSignatureError):
            raise statuses.unauthorized()

        self.userid_blacklist_check(identity.id)
        return identity

    def userid_blacklist_check(self, userid):
        # FIXME: use redis hash, hset, hget
        if self.redis is not None and \
                self.redis.sismember(FORBIDDEN_REDIS_KEY, userid):
            raise statuses.unauthorized()

    def userid_blacklist_set(self, id):
        self.redis.sadd(FORBIDDEN_REDIS_KEY, id)

    def userid_blacklist_unset(self, id):
        self.redis.srem(FORBIDDEN_REDIS_KEY, id)

    def _logintoken_cookie_set(self, req, token):
        settings = self.settings.logintoken.cookie

        # Set cookie
        entry = req.response.setcookie(settings.key, token)

        if settings.secure:
            entry['secure'] = settings.secure

        if settings.httponly:
            entry['httponly'] = settings.httponly

        if settings.domain:
            entry['domain'] = settings.domain

        if settings.samesite:
            entry['samesite'] = settings.samesite

        entry['path'] = settings.path or req.path
        return entry

    def logintoken_cookie_set(self, req, token):
        settings = self.settings.logintoken
        entry = self._logintoken_cookie_set(req, token)
        if settings.maxage:
            entry['max-age'] = settings.maxage

    def logintoken_cookie_delete(self, req):
        entry = self._logintoken_cookie_set(req, '')
        entry['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
        return entry

    def __call__(self, roles=None):
        if isinstance(roles, str):
            roles = [i.strip() for i in roles.split(',')]

        def decorator(handler):
            @functools.wraps(handler)
            def wrapper(req, *args, **kw):
                req.identity = self.logintoken_verify(req)
                if roles is not None:
                    req.identity.authorize(*roles)

                return handler(req, *args, **kw)

            return wrapper
        return decorator
