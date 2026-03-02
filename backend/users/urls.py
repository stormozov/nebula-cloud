"""
URL configuration for users app.

This module defines URL patterns for user authentication, management,
and admin endpoints. Uses DRF DefaultRouter for ViewSet-based routing.

Endpoints:
    Authentication:
        POST   /api/users/auth/register/          - User registration
        POST   /api/users/auth/login/             - User login
        POST   /api/users/auth/logout/            - User logout
        POST   /api/users/auth/refresh/           - Token refresh
        POST   /api/users/auth/password/change/   - Password change

    User Profile:
        GET    /api/users/users/me/               - Current user profile
        PUT    /api/users/users/me/               - Update current user
        PATCH  /api/users/users/me/               - Partial update

    Admin User Management:
        GET    /api/users/admin/users/            - List all users (admin only)
        GET    /api/users/admin/users/{id}/       - Get user details (admin only)
        PUT    /api/users/admin/users/{id}/       - Update user (admin only)
        PATCH  /api/users/admin/users/{id}/       - Partial update (admin only)
        DELETE /api/users/admin/users/{id}/       - Delete user (admin only)
        POST   /api/users/admin/users/{id}/password/ - Reset password (admin only)
        POST   /api/users/admin/users/{id}/toggle-admin/ - Toggle admin status
        GET    /api/users/admin/users/{id}/storage-stats/ - Get storage stats
"""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from users.views import (
    AdminUserViewSet,
    CurrentUserView,
    CustomTokenRefreshView,
    LoginView,
    LogoutView,
    PasswordChangeView,
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
    path(
        "auth/password/change/",
        PasswordChangeView.as_view(),
        name="password_change",
    ),
    # ==============================================================================================
    # User profile endpoints
    # ==============================================================================================
    path("users/me/", CurrentUserView.as_view(), name="current_user"),
    # ==============================================================================================
    # Admin endpoints
    # ==============================================================================================
    path("admin/", include(admin_router.urls)),
]
