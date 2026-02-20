"""
Services for user authentication.
"""

from typing import Self

from rest_framework_simplejwt.tokens import RefreshToken

from users.models import UserAccount


class AuthResponseBuilder:
    """Builder pattern for complex auth responses."""

    def __init__(self, user: UserAccount):
        self.user = user
        self._tokens = None
        self._extras = {}

    def with_tokens(self, refresh: RefreshToken = None) -> Self:
        """
        Sets the refresh token for the user and returns the current instance
        of the `AuthResponseBuilder` class.
        """
        self._tokens = refresh or RefreshToken.for_user(self.user)
        return self

    def with_metadata(self, **kwargs) -> Self:
        """
        Updates the metadata of the `AuthResponseBuilder` instance with the provided keyword
        arguments.
        """
        self._extras.update(kwargs)
        return self

    def build(self) -> dict:
        """
        Builds and returns a dictionary containing the access token, refresh token,
        user information, and any additional metadata.
        """

        if not self._tokens:
            raise RuntimeError("Tokens not initialized. Call with_tokens() first to set tokens.")

        return {
            "access": str(self._tokens.access_token),
            "refresh": str(self._tokens),
            "user": self.user,
            **self._extras,
        }
