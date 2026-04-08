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
