"""
Custom throttling classes for authentication endpoints.

Provides rate limiting to protect against brute force attacks.
"""

from rest_framework.throttling import AnonRateThrottle


class LoginRateThrottle(AnonRateThrottle):
    """
    Throttle class for login endpoint.

    Limits anonymous users to prevent brute force attacks.
    More restrictive than standard AnonRateThrottle.
    """

    scope = "login"

    def get_cache_key(self, request, view) -> str | None:
        """
        Generate cache key based on username to prevent brute force on specific account.

        This prevents attackers from trying many passwords for the same username.
        """
        username = request.data.get("username")

        if request.user.is_authenticated or not username:
            return None

        return self.cache_format % {
            "scope": self.scope,
            "ident": self.get_ident(request) + f"_{username}",
        }


class RegisterRateThrottle(AnonRateThrottle):
    """
    Throttle class for registration endpoint.

    Prevents spam registration and abuse of the registration system.
    """

    scope = "register"


class PasswordResetRateThrottle(AnonRateThrottle):
    """
    Throttle class for password reset endpoint.

    Prevents abuse of password reset functionality.
    """

    scope = "password_reset"

    def get_cache_key(self, request, view) -> str | None:
        """
        Generate cache key based on email to prevent spam to specific email.
        """
        email = request.data.get("email")

        if not email:
            return None

        return self.cache_format % {
            "scope": self.scope,
            "ident": self.get_ident(request) + f"_{email}",
        }
