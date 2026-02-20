"""
Views for 🇺ser profile managment

This module provides API endpoints for:
- Current user profile management (CurrentUserView)
- Password change (PasswordChangeView)
"""

from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from core.utils import get_client_ip
from users.models import UserAccount
from users.serializers import PasswordChangeSerializer, UserSerializer

from ..loggers import auth_logger, logger

# ==============================================================================
# CURRENT USER
# ==============================================================================


class CurrentUserView(generics.RetrieveUpdateAPIView):
    """
    API endpoint for current user profile.

    `GET /api/auth/me/`
    Returns the current authenticated user's profile data.

    `PUT /api/auth/me/`
    Updates the current user's profile (first_name, last_name).
    """

    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self) -> UserAccount:
        """Return the current authenticated user."""
        return self.request.user

    def retrieve(self, request, *args, **kwargs) -> Response:
        """Get current user profile."""

        instance = self.get_object()
        serializer = self.get_serializer(instance)

        logger.info(
            "User profile accessed: email=%s, IP=%s",
            request.user.email,
            get_client_ip(request),
        )

        return Response(serializer.data)

    def update(self, request, *args, **kwargs) -> Response:
        """
        Update current user profile.

        Only allows updating first_name and last_name.
        """

        # 1. Get target user
        partial = kwargs.pop("partial", False)
        instance = self.get_object()

        # 2. Validate data via serializer
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        # 3. Update user
        self.perform_update(serializer)

        # 4. Return response with updated data
        logger.info(
            "User profile updated: email=%s, updated_fields=%s, IP=%s",
            request.user.email,
            list(request.data.keys()),
            get_client_ip(request),
        )

        return Response(serializer.data)


class PasswordChangeView(APIView):
    """
    API endpoint for password change.

    `POST /api/auth/password/change/`
    Changes the authenticated user's password.
    """

    serializer_class = PasswordChangeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request) -> Response:
        """Change the authenticated user's password."""

        # 1. Validate data via serializer
        serializer = PasswordChangeSerializer(data=request.data, context={"request": request})

        if not serializer.is_valid():
            auth_logger.warning(
                "Failed password change attempt: user=%s, errors=%s, IP=%s",
                request.user.email,
                serializer.errors,
                get_client_ip(request),
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # 2. Update password
        user = request.user
        new_password: str = serializer.validated_data["new_password"]
        user.set_password(new_password)
        user.save()

        # 3. Return response with success message
        auth_logger.info(
            "User password changed successfully: email=%s, username=%s, IP=%s",
            user.email,
            user.username,
            get_client_ip(request),
        )

        return Response({"detail": "Пароль успешно изменён."}, status=status.HTTP_200_OK)

    def handle_exception(self, exc):
        """Handle exceptions and log them."""

        user_email = (
            getattr(self.request.user, "email", "anonymous")
            if hasattr(self, "request") and self.request.user
            else "unknown"
        )
        user_ip = get_client_ip(self.request) if hasattr(self, "request") else "unknown"

        auth_logger.error(
            "Password change failed: %s, user=%s, IP=%s",
            str(exc),
            user_email,
            user_ip,
        )

        return super().handle_exception(exc)
