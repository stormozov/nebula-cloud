"""
URL configuration for users app.

This module defines URL patterns for user authentication, management,
and admin endpoints. Uses DRF DefaultRouter for ViewSet-based routing.

Endpoints:
    Authentication:
        POST /api/users/auth/register/  - Register new user
        POST /api/users/auth/login/     - Login and get tokens
        POST /api/users/auth/logout/    - Logout and blacklist token
        POST /api/users/auth/refresh/   - Refresh access token

    User Profile:
        GET    /api/users/me/                    - Get current user profile
        PUT    /api/users/me/                    - Full update profile
        PATCH  /api/users/me/                    - Partial update profile
        POST   /api/users/me/password/           - Change password
        GET    /api/users/me/storage-summary/    - Get storage statistics
        GET    /api/users/me/session-info/       - Get current session details
        POST   /api/users/me/deactivate/         - Deactivate own account

    Admin User Management:
        GET    /api/admin/users/              - List all users
        GET    /api/admin/users/{id}/         - Get user details
        PUT    /api/admin/users/{id}/         - Update user data
        DELETE /api/admin/users/{id}/         - Delete user
        POST   /api/admin/users/{id}/password/ - Reset user password
        POST   /api/admin/users/{id}/toggle-admin/ - Toggle admin status
        GET    /api/admin/users/{id}/storage-stats/ - Get storage statistics
"""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from users.views import (
    AdminUserViewSet,
    CurrentUserView,
    CustomTokenRefreshView,
    LoginView,
    LogoutView,
    RegisterView,
)

app_name = "users"

# Router for admin user management ViewSet
admin_router = DefaultRouter()
admin_router.register(r"users", AdminUserViewSet, basename="admin-user")
admin_router.include_format_suffixes = False

urlpatterns = [
    # ==============================================================================================
    # Authentication endpoints
    # ==============================================================================================
    path("auth/register/", RegisterView.as_view(), name="register"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/logout/", LogoutView.as_view(), name="logout"),
    path("auth/refresh/", CustomTokenRefreshView.as_view(), name="token_refresh"),
    # ==============================================================================================
    # User profile endpoints
    # ==============================================================================================
    path(
        "users/me/",
        CurrentUserView.as_view(
            {
                "get": "retrieve",
                "put": "update",
                "patch": "partial_update",
            }
        ),
        name="current-user-detail",
    ),
    path(
        "users/me/password/",
        CurrentUserView.as_view({"post": "change_password"}),
        name="current-user-password",
    ),
    path(
        "users/me/storage-summary/",
        CurrentUserView.as_view({"get": "storage_summary"}),
        name="current-user-storage-summary",
    ),
    path(
        "users/me/session-info/",
        CurrentUserView.as_view({"get": "session_info"}),
        name="current-user-session-info",
    ),
    path(
        "users/me/deactivate/",
        CurrentUserView.as_view({"post": "deactivate_account"}),
        name="current-user-deactivate",
    ),
    # ==============================================================================================
    # Admin endpoints
    # ==============================================================================================
    path("admin/", include(admin_router.urls)),
]
