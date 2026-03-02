"""
Views for users app.
"""

from .admin_views import AdminUserViewSet
from .auth_views import CustomTokenRefreshView, LoginView, LogoutView, RegisterView
from .views_users import CurrentUserView, PasswordChangeView

__all__ = [
    # Admin endpoints
    "AdminUserViewSet",
    # Authentication endpoints
    "LoginView",
    "LogoutView",
    "RegisterView",
    "CustomTokenRefreshView",
    # User profile endpoints
    "CurrentUserView",
    "PasswordChangeView",
]
