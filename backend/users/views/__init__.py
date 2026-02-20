"""
Views for users app.
"""

from .views_admin import (
    AdminPasswordResetView,
    AdminToggleAdminView,
    AdminUserDetailView,
    AdminUserListView,
    AdminUserStorageStatsView,
)
from .views_auth import CustomTokenRefreshView, LoginView, LogoutView, RegisterView
from .views_users import CurrentUserView, PasswordChangeView

__all__ = [
    # Admin endpoints
    "AdminPasswordResetView",
    "AdminToggleAdminView",
    "AdminUserDetailView",
    "AdminUserListView",
    "AdminUserStorageStatsView",
    "CustomTokenRefreshView",
    # Authentication endpoints
    "LoginView",
    "LogoutView",
    "RegisterView",
    # User profile endpoints
    "CurrentUserView",
    "PasswordChangeView",
]
