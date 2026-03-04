"""
Exceptions for users app.
"""

from rest_framework import status


class AdminUserActionError(Exception):
    """Base exception for admin user actions."""

    def __init__(self, message: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        self.message = message
        self.status_code = status_code
        super().__init__(message)
