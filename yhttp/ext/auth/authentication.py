import os
import jwt
import hashlib
import functools
from datetime import datetime, timedelta, timezone

import redis
from pymlconf import MergableDict
from yhttp import statuses
from yhttp.lazyattribute import lazyattribute


FORBIDDEN_REDIS_KEY = 'yhttp-auth-forbidden'


class Identity:
    def __init__(self, payload):
        assert payload['id'] is not None
        self.payload = payload

    def __getattr__(self, attr):
        try:
            return self.payload[attr]
        except KeyError:
            raise AttributeError()

    def authorize(self, roles):
        if 'roles' not in self.payload:
            raise statuses.forbidden()

        for r in roles:
            if r in self.roles:
                return r

        raise statuses.forbidden()


class Authenticator:
    redis = None
    default_settings = MergableDict('''
      redis:
        host: localhost
        port: 6379
        db: 0

      token:
        algorithm: HS256
        secret: foobar
        maxage: 3600 # seconds
        leeway: 10 # seconds

      refresh:
        key: yhttp-refresh-token
        algorithm: HS256
        secret: quxquux
        secure: true
        httponly: true
        maxage: 2592000 # 1 Month
        leeway: 10 # seconds
        domain:
        path:
        samesite: Strict

      csrf:
        key: yhttp-csrf-token
        secure: true
        httponly: true
        maxage: 60 # 1 Minute
        samesite: Strict
        domain:
        path:

      oauth2:
        state:
          algorithm: HS256
          secret: quxquux
          maxage: 60 # 1 Minute
          leeway: 10 # seconds

    ''')

    def __init__(self, settings=None):
        self.settings = settings if settings else self.default_settings
        self.redis = redis.Redis(**self.settings.redis)

    ##########
    # OAuth2 #
    ##########

    @lazyattribute
    def oauth2_state_maxage(self):
        return self.settings.oauth2.state.maxage

    @lazyattribute
    def oauth2_state_secret(self):
        return self.settings.oauth2.state.secret

    @lazyattribute
    def oauth2_state_algorithm(self):
        return self.settings.oauth2.state.algorithm

    @lazyattribute
    def oauth2_state_leeway(self):
        return self.settings.oauth2.state.leeway

    def dump_oauth2_state(self, req, redirect_url, attrs=None):
        payload = {
            'exp': self._exp(self.oauth2_state_maxage),
            'redurl': redirect_url,
            'id': self.create_csrftoken(req)
        }
        if attrs:
            payload.update(attrs)

        return jwt.encode(
            payload,
            self.oauth2_state_secret,
            algorithm=self.oauth2_state_algorithm
        )

    def decode_oauth2_state(self, state):
        return jwt.decode(
            state,
            self.oauth2_state_secret,
            leeway=self.oauth2_state_leeway,
            algorithms=[self.oauth2_state_algorithm]
        )

    def verify_oauth2_state(self, req, state):
        if state is None:
            raise statuses.unauthorized()

        try:
            identity = Identity(self.decode_oauth2_state(state))
        except (KeyError, jwt.DecodeError, jwt.ExpiredSignatureError):
            raise statuses.unauthorized()

        self.verify_csrftoken(req, identity.id)
        return identity

    ########
    # CSRF #
    ########

    @lazyattribute
    def csrf_cookiekey(self):
        return self.settings.csrf.key

    def set_csrfcookie(self, req, token):
        settings = self.settings.csrf

        # Set cookie
        entry = req.response.setcookie(self.csrf_cookiekey, token)

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

    def create_csrftoken(self, req):
        # Create a state token to prevent request forgery.
        token = hashlib.sha256(os.urandom(1024)).hexdigest()

        self.set_csrfcookie(req, token)
        return token

    def verify_csrftoken(self, req, token):
        ctoken = req.cookies.get(self.csrf_cookiekey)
        if ctoken is None:
            raise statuses.forbidden()

        if ctoken.value != token:
            raise statuses.forbidden()

    ##########
    # Refresh
    ##########

    @lazyattribute
    def refresh_cookiekey(self):
        return self.settings.refresh.key

    @lazyattribute
    def refresh_secret(self):
        return self.settings.refresh.secret

    @lazyattribute
    def refresh_maxage(self):
        return self.settings.refresh.maxage

    @lazyattribute
    def refresh_leeway(self):
        return self.settings.refresh.leeway

    @lazyattribute
    def refresh_algorithm(self):
        return self.settings.refresh.algorithm

    def _set_refreshtoken(self, req, token):
        settings = self.settings.refresh

        # Set cookie
        entry = req.response.setcookie(self.refresh_cookiekey, token)

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

    def delete_refreshtoken(self, req):
        entry = self._set_refreshtoken(req, '')
        entry['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
        del entry['max-age']
        return entry

    def set_refreshtoken(self, req, id, attrs=None):
        settings = self.settings.refresh
        token = self.dump_refreshtoken(id, attrs)

        # Set cookie
        entry = self._set_refreshtoken(req, token)
        entry['max-age'] = settings.maxage
        return entry

    def _exp(self, seconds):
        # TODO: Stupid explicit is better than comprehensive implicit.
        return datetime.now(tz=timezone.utc) + timedelta(seconds=seconds)

    def dump_refreshtoken(self, id, attrs=None):
        payload = {
            'id': id,
            'refresh': True,
            'exp': self._exp(self.refresh_maxage)
        }
        if attrs:
            payload.update(attrs)

        return jwt.encode(
            payload,
            self.refresh_secret,
            algorithm=self.refresh_algorithm
        )

    def verify_refreshtoken(self, req):
        if self.refresh_cookiekey not in req.cookies:
            raise statuses.unauthorized()

        token = req.cookies[self.refresh_cookiekey].value
        try:
            identity = Identity(jwt.decode(
                token,
                self.refresh_secret,
                leeway=self.refresh_leeway,
                algorithms=[self.refresh_algorithm]
            ))

        except (KeyError, jwt.DecodeError, jwt.ExpiredSignatureError):
            raise statuses.unauthorized()

        self.check_blacklist(identity.id)
        return identity

    #########
    # Token #
    #########

    @lazyattribute
    def token_secret(self):
        return self.settings.token.secret

    @lazyattribute
    def token_maxage(self):
        return self.settings.token.maxage

    @lazyattribute
    def token_leeway(self):
        return self.settings.token.leeway

    @lazyattribute
    def token_algorithm(self):
        return self.settings.token.algorithm

    def dump(self, id, attrs=None):
        payload = {
            'id': id,
            'exp': self._exp(self.token_maxage)
        }
        if attrs:
            payload.update(attrs)

        return jwt.encode(
            payload,
            self.token_secret,
            algorithm=self.token_algorithm
        )

    def dump_from_refreshtoken(self, refresh, attrs=None):
        payload = refresh.payload.copy()
        del payload['refresh']

        if attrs:
            payload.update(attrs)

        payload['exp'] = self._exp(self.token_maxage)
        return jwt.encode(
            payload,
            self.token_secret,
            algorithm=self.token_algorithm
        )

    def check_blacklist(self, userid):
        # FIXME: use redis hash, hset, hget
        if self.redis is not None and \
                self.redis.sismember(FORBIDDEN_REDIS_KEY, userid):
            raise statuses.unauthorized()

    def decode_token(self, token):
        return jwt.decode(
            token,
            self.token_secret,
            leeway=self.token_leeway,
            algorithms=[self.token_algorithm]
        )

    def verify_token(self, req):
        token = req.headers.get('Authorization')

        if token is None or not token.startswith('Bearer '):
            raise statuses.unauthorized()

        try:
            identity = Identity(self.decode_token(token[7:]))
        except (KeyError, jwt.DecodeError, jwt.ExpiredSignatureError):
            raise statuses.unauthorized()

        self.check_blacklist(identity.id)
        return identity

    def preventlogin(self, id):
        self.redis.sadd(FORBIDDEN_REDIS_KEY, id)

    def permitlogin(self, id):
        self.redis.srem(FORBIDDEN_REDIS_KEY, id)


def authenticate(app, roles=None):
    if isinstance(roles, str):
        roles = [i.strip() for i in roles.split(',')]

    def decorator(handler):
        @functools.wraps(handler)
        def wrapper(req, *args, **kw):
            req.identity = app.auth.verify_token(req)
            if roles is not None:
                req.identity.authorize(roles)

            return handler(req, *args, **kw)

        return wrapper
    return decorator
