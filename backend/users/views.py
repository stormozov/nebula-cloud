"""
Views for user authentication and management.

This module provides API endpoints for:
- User registration
- User login/logout
- Token refresh
- Current user profile management
- Password change
- AdminUserListView
- AdminUserDetailView
- AdminUserUpdateView
- AdminToggleAdminView
"""

from django.db import models
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView

from storage.models import File
from users.models import UserAccount
from users.permissions import IsAdminUser
from users.serializers import (
    AdminPasswordResetSerializer,
    AdminToggleAdminSerializer,
    AdminUserDetailSerializer,
    AdminUserListSerializer,
    AdminUserUpdateSerializer,
    PasswordChangeSerializer,
    TokenResponseSerializer,
    UserLoginSerializer,
    UserRegistrationSerializer,
    UserSerializer,
)
from users.throttles import LoginRateThrottle, RegisterRateThrottle
from utils.ip_utils import get_client_ip

from .logging import auth_logger, logger

# ==============================================================================
# AUTHENTICATION
# ==============================================================================


class RegisterView(generics.CreateAPIView):
    """
    API endpoint for user registration.

    `POST /api/auth/register/`
    Creates a new user account and returns JWT tokens.
    """

    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]
    throttle_classes = [RegisterRateThrottle]

    def create(self, request, *args, **kwargs) -> Response:
        """
        Handle user registration.

        Returns:
            Response: JWT tokens and user data on success.
        """

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Create user
        user = serializer.save()

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)

        # Prepare response data
        token_data = {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": user,
        }

        # Serialize response
        response_serializer = TokenResponseSerializer(token_data)

        # Log successful registration
        auth_logger.info(
            "User registered successfully: email=%s, username=%s, IP=%s",
            user.email,
            user.username,
            get_client_ip(request),
        )

        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    def handle_exception(self, exc):
        """Handle exceptions and log them."""
        auth_logger.error(
            "Registration failed: %s, IP=%s",
            str(exc),
            get_client_ip(self.request),
        )
        return super().handle_exception(exc)


class LoginView(APIView):
    """
    API endpoint for user login.

    `POST /api/auth/login/`
    Authenticates user and returns JWT tokens.
    """

    serializer_class = UserLoginSerializer
    permission_classes = [permissions.AllowAny]
    throttle_classes = [LoginRateThrottle]

    def post(self, request) -> Response:
        """
        Handle user login.

        Returns:
            Response: JWT tokens and user data on success.
        """

        serializer = UserLoginSerializer(data=request.data)

        if not serializer.is_valid():
            # Log failed login attempt
            email = request.data.get("email", "unknown")
            auth_logger.warning(
                "Failed login attempt: email=%s, errors=%s, IP=%s",
                email,
                serializer.errors,
                get_client_ip(request),
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data["user"]

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)

        # Prepare response data
        token_data = {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": user,
        }

        # Serialize response
        response_serializer = TokenResponseSerializer(token_data)

        # Log successful login
        auth_logger.info(
            "User logged in successfully: email=%s, username=%s, IP=%s",
            user.email,
            user.username,
            get_client_ip(request),
        )

        return Response(response_serializer.data, status=status.HTTP_200_OK)


class LogoutView(APIView):
    """
    API endpoint for user logout.

    `POST /api/auth/logout/`
    Blacklists the refresh token to prevent further use.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request) -> Response:
        """
        Handle user logout.

        Blacklists the provided refresh token.

        Returns:
            Response: Success message on successful logout.
        """
        try:
            refresh_token = request.data.get("refresh")

            if not refresh_token:
                auth_logger.warning(
                    "Logout failed: missing refresh token, user=%s, IP=%s",
                    request.user.email,
                    get_client_ip(request),
                )
                return Response(
                    {"detail": "Refresh token is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Blacklist the refresh token
            token = RefreshToken(refresh_token)
            token.blacklist()

            # Log successful logout
            auth_logger.info(
                "User logged out successfully: email=%s, username=%s, IP=%s",
                request.user.email,
                request.user.username,
                get_client_ip(request),
            )

            return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
        except TokenError as e:
            auth_logger.error(
                "Logout failed - invalid token: %s, user=%s, IP=%s",
                str(e),
                request.user.email,
                get_client_ip(request),
            )
            return Response(
                {"detail": f"Invalid token: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            auth_logger.error(
                "Logout failed: %s, user=%s, IP=%s",
                str(e),
                request.user.email,
                get_client_ip(request),
            )
            return Response(
                {"detail": f"Logout failed: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )


# ==============================================================================
# TOKEN REFRESH
# ==============================================================================


class CustomTokenRefreshView(TokenRefreshView):
    """
    API endpoint for refreshing access token.

    `POST /api/auth/refresh/`
    Returns a new access token using a valid refresh token.
    """


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
        """
        Return the current authenticated user.

        Returns:
            UserAccount: The currently authenticated user.
        """
        return self.request.user

    def retrieve(self, request, *args, **kwargs) -> Response:
        """
        Get current user profile.

        Returns:
            Response: User profile data.
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance)

        # Log profile access
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

        Returns:
            Response: Updated user profile data.
        """

        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        # Log profile update
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
        """
        Change the authenticated user's password.

        Returns:
            Response: Success message on successful password change.
        """

        serializer = PasswordChangeSerializer(data=request.data, context={"request": request})

        if not serializer.is_valid():
            auth_logger.warning(
                "Failed password change attempt: user=%s, errors=%s, IP=%s",
                request.user.email,
                serializer.errors,
                get_client_ip(request),
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Change password
        user = request.user
        new_password: str = serializer.validated_data["new_password"]
        user.set_password(new_password)
        user.save()

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


# ==================================================================================================
# ADMIN USER MANAGEMENT
# ==================================================================================================


class AdminUserListView(generics.ListAPIView):
    """
    API endpoint for listing all users (admin only).
    `GET /api/admin/users/`
    Returns a list of all users with their storage statistics.
    """

    serializer_class = AdminUserListSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]

    def get_queryset(self):
        """Return all users ordered by username."""
        return UserAccount.objects.all().order_by("username")


class AdminUserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    API endpoint for user details, update, and delete (admin only).
    `GET /api/admin/users/{id}/`
    `PUT /api/admin/users/{id}/`
    `DELETE /api/admin/users/{id}/`
    """

    queryset = UserAccount.objects.all()
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]

    def get_serializer_class(self):
        """Return appropriate serializer based on request method."""
        return (
            AdminUserUpdateSerializer
            if self.request.method in ["PUT", "PATCH"]
            else AdminUserDetailSerializer
        )

    def retrieve(self, request, *args, **kwargs) -> Response:
        """Get user details with storage statistics."""

        instance = self.get_object()
        serializer = self.get_serializer(instance)

        logger.info(
            "Admin accessed user details: admin=%s, target_user=%s, IP=%s",
            request.user.email,
            instance.email,
            get_client_ip(request),
        )

        return Response(serializer.data)

    def update(self, request, *args, **kwargs) -> Response:
        """Update user data."""

        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        logger.info(
            "Admin updated user: admin=%s, target_user=%s, fields=%s, IP=%s",
            request.user.email,
            instance.email,
            list(request.data.keys()),
            get_client_ip(request),
        )

        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs) -> Response:
        """Delete user."""

        instance = self.get_object()
        user_email = instance.email
        user_id = instance.id

        # Prevent admin from deleting themselves
        if instance.id == request.user.id:
            auth_logger.warning(
                "Admin attempted to delete own account: admin=%s, IP=%s",
                request.user.email,
                get_client_ip(request),
            )
            return Response(
                {"detail": "Нельзя удалить собственную учётную запись."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        self.perform_destroy(instance)

        auth_logger.info(
            "Admin deleted user: admin=%s, deleted_user=%s (id=%d), IP=%s",
            request.user.email,
            user_email,
            user_id,
            get_client_ip(request),
        )

        return Response(
            {"detail": "Пользователь успешно удалён."},
            status=status.HTTP_200_OK,
        )


class AdminPasswordResetView(APIView):
    """
    API endpoint for admin to reset user password.
    `POST /api/admin/users/{id}/password/`
    """

    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = AdminPasswordResetSerializer

    def post(self, request, pk) -> Response:
        """Reset password for specified user."""

        try:
            user = UserAccount.objects.get(pk=pk)
        except UserAccount.DoesNotExist:  # pylint: disable=no-member
            return Response(
                {"detail": "Пользователь не найден."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Prevent admin from resetting their own password via this endpoint
        if user.id == request.user.id:
            return Response(
                {"detail": "Используйте endpoint смены пароля для себя."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = AdminPasswordResetSerializer(data=request.data)
        if not serializer.is_valid():
            auth_logger.warning(
                "Admin password reset failed: admin=%s, target_user=%s, errors=%s, IP=%s",
                request.user.email,
                user.email,
                serializer.errors,
                get_client_ip(request),
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Set new password
        new_password = serializer.validated_data["new_password"]
        user.set_password(new_password)
        user.save()

        auth_logger.info(
            "Admin reset user password: admin=%s, target_user=%s, IP=%s",
            request.user.email,
            user.email,
            get_client_ip(request),
        )

        return Response(
            {"detail": "Пароль пользователя успешно сброшен."},
            status=status.HTTP_200_OK,
        )


class AdminToggleAdminView(APIView):
    """
    API endpoint for toggling user admin status.
    `POST /api/admin/users/{id}/toggle-admin/`
    """

    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = AdminToggleAdminSerializer

    def post(self, request, pk) -> Response:
        """Toggle admin status for specified user."""

        try:
            user = UserAccount.objects.get(pk=pk)
        except UserAccount.DoesNotExist:  # pylint: disable=no-member
            return Response(
                {"detail": "Пользователь не найден."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Prevent admin from removing their own admin status
        if user.id == request.user.id:
            return Response(
                {"detail": "Нельзя изменить собственный статус администратора."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = AdminToggleAdminSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Update admin status
        user.is_staff = serializer.validated_data["is_admin"]
        user.save()

        auth_logger.info(
            "Admin toggled user admin status: admin=%s, target_user=%s, new_status=%s, IP=%s",
            request.user.email,
            user.email,
            user.is_staff,
            get_client_ip(request),
        )

        return Response(
            {
                "detail": "Статус администратора успешно изменён.",
                "is_admin": user.is_staff,
            },
            status=status.HTTP_200_OK,
        )


class AdminUserStorageStatsView(APIView):
    """
    API endpoint for getting detailed user storage statistics.
    `GET /api/admin/users/{id}/storage-stats/`
    """

    permission_classes = [permissions.IsAuthenticated, IsAdminUser]

    def get(self, request, pk) -> Response:
        """Get storage statistics for specified user."""

        try:
            user = UserAccount.objects.get(pk=pk)
        except UserAccount.DoesNotExist:  # pylint: disable=no-member
            return Response(
                {"detail": "Пользователь не найден."},
                status=status.HTTP_404_NOT_FOUND,
            )

        user_files = File.objects.filter(owner=user)  # pylint: disable=no-member
        total_size = user_files.aggregate(total=models.Sum("size"))["total"] or 0
        file_count = user_files.count()

        stats = {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "storage_path": user.storage_path,
            "file_count": file_count,
            "total_size": total_size,
            "total_size_formatted": self._format_size(total_size),
        }

        logger.info(
            "Admin accessed user storage stats: admin=%s, target_user=%s, IP=%s",
            request.user.email,
            user.email,
            get_client_ip(request),
        )

        return Response(stats, status=status.HTTP_200_OK)

    def _format_size(self, size_bytes: int) -> str:
        """Format bytes to human-readable size."""
        return next(
            f"{size_bytes / (1024**i):.2f} {unit}"
            for i, unit in enumerate(["B", "KB", "MB", "GB", "TB", "PB"])
            if size_bytes < 1024 ** (i + 1) or i == 5
        )
