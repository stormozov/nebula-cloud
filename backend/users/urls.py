"""
URL configuration for users app.

This module defines URL patterns for user authentication and management endpoints.
"""

from django.urls import path

from users.views import (
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
]
