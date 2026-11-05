"""
Frontend container authentication.
"""

from shared.auth import BaseAuth


class FrontendAuth(BaseAuth):
    REQUIRED_ENV = (BaseAuth.CONTAINER_KEY_ENV, BaseAuth.JWT_SECRET_ENV)
