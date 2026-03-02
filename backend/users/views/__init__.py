"""
Views for users app.
"""

from .admin_views import AdminUserViewSet
from .views_auth import CustomTokenRefreshView, LoginView, LogoutView, RegisterView
from .views_users import CurrentUserView, PasswordChangeView

__all__ = [
    # Admin endpoints
    "AdminUserViewSet",
    "CustomTokenRefreshView",
    # Authentication endpoints
    "LoginView",
    "LogoutView",
    "RegisterView",
    # User profile endpoints
    "CurrentUserView",
    "PasswordChangeView",
]
