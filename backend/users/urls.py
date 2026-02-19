"""
URL configuration for users app.

This module defines URL patterns for user authentication and management endpoints.
"""

from django.urls import path

from users.views import (
    AdminPasswordResetView,
    AdminToggleAdminView,
    AdminUserDetailView,
    AdminUserListView,
    AdminUserStorageStatsView,
    CurrentUserView,
    CustomTokenRefreshView,
    LoginView,
    LogoutView,
    PasswordChangeView,
    RegisterView,
)

app_name = "users"

urlpatterns = [
    # Authentication endpoints
    path("auth/register/", RegisterView.as_view(), name="register"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/logout/", LogoutView.as_view(), name="logout"),
    path("auth/refresh/", CustomTokenRefreshView.as_view(), name="token_refresh"),
    path("auth/password/change/", PasswordChangeView.as_view(), name="password_change"),
    # User profile endpoints
    path("users/me/", CurrentUserView.as_view(), name="current_user"),
    # Admin endpoints
    path("admin/users/", AdminUserListView.as_view(), name="admin_user_list"),
    path("admin/users/<int:pk>/", AdminUserDetailView.as_view(), name="admin_user_detail"),
    path(
        "admin/users/<int:pk>/password/",
        AdminPasswordResetView.as_view(),
        name="admin_password_reset",
    ),
    path(
        "admin/users/<int:pk>/toggle-admin/",
        AdminToggleAdminView.as_view(),
        name="admin_toggle_admin",
    ),
    path(
        "admin/users/<int:pk>/storage-stats/",
        AdminUserStorageStatsView.as_view(),
        name="admin_storage_stats",
    ),
]
