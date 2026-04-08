import os
import hashlib
import functools
from typing import Union
from datetime import datetime, timedelta, timezone

from yhttp.core import statuses, Request




class Authenticator:
    redis = None

    def __init__(self, settings):
        self.settings = settings

    def accesstoken_create(self, id, roles: list[str]) -> AccessToken:
        return AccessToken(self.settings.accesstoken, id, roles)

    def csrftoken_create(self) -> CSRFToken:
        return CSRFToken(self.settings.csrftoken)

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


    def accesstoken_dump_from_refreshtoken(self, refresh, attrs=None):
        settings = self.settings.accesstoken
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

    def _accesstoken_cookie_set(self, req, token):
        settings = self.settings.accesstoken.cookie

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

    def accesstoken_cookie_set(self, req, token):
        settings = self.settings.accesstoken
        entry = self._accesstoken_cookie_set(req, token)
        if settings.maxage:
            entry['max-age'] = settings.maxage

    def accesstoken_cookie_delete(self, req):
        entry = self._accesstoken_cookie_set(req, '')
        entry['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
        return entry

    def __call__(self, roles=None):
        if isinstance(roles, str):
            roles = [i.strip() for i in roles.split(',')]

        def decorator(handler):
            @functools.wraps(handler)
            def wrapper(req, *args, **kw):
                req.identity = self.accesstoken_verify(req)
                if roles is not None:
                    req.identity.isinroles(*roles)

                return handler(req, *args, **kw)

            return wrapper
        return decorator
