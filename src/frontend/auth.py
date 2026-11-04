"""
Frontend container authentication.

The frontend never creates or stores accounts. It only validates the
access tokens that the backend issued (same JWT_SECRET), so it needs no
user store
"""

from shared.auth import BaseAuth


class FrontendAuth(BaseAuth):
    REQUIRED_ENV = (BaseAuth.CONTAINER_KEY_ENV, BaseAuth.JWT_SECRET_ENV)
