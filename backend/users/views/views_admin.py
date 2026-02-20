"""
Views for admin user managment.

This module provides API endpoints for:
- Listing users (AdminUserListView)
- Detailed user information (AdminUserDetailView)
- Updating user data (AdminUserUpdateView)
- Password reset (AdminPasswordResetView)
- Toggling admin status (AdminToggleAdminView)
"""

from django.db import models
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from core.utils import get_client_ip
from users.exceptions import AdminUserActionError
from users.models import UserAccount
from users.permissions import IsAdminUser
from users.serializers import (
    AdminPasswordResetSerializer,
    AdminToggleAdminSerializer,
    AdminUserDetailSerializer,
    AdminUserListSerializer,
    AdminUserUpdateSerializer,
)
from users.services import (
    calculate_storage_stats,
    get_user_by_id_or_raise,
    reset_user_password,
    toggle_admin_status,
    validate_not_self_action,
)

from ..loggers import auth_logger, logger

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

    def get_queryset(self) -> models.query.QuerySet:
        """Return all users ordered by username."""
        return UserAccount.objects.all().order_by("username")


class AdminUserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    API endpoint for user details, update, and delete (admin only).

    `GET /api/admin/users/{id}/`
    Gets user details with storage statistics.

    `PUT /api/admin/users/{id}/`
    Updates user data.

    `DELETE /api/admin/users/{id}/`
    Deletes a user.
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

        # 1. Get target user
        instance = self.get_object()

        # 2. Validate data via serializer
        serializer = self.get_serializer(instance)

        # 3. Return response with user details
        logger.info(
            "Admin accessed user details: admin=%s, target_user=%s, IP=%s",
            request.user.email,
            instance.email,
            get_client_ip(request),
        )

        return Response(serializer.data)

    def update(self, request, *args, **kwargs) -> Response:
        """Update user data."""

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
            "Admin updated user: admin=%s, target_user=%s, fields=%s, IP=%s",
            request.user.email,
            instance.email,
            list(request.data.keys()),
            get_client_ip(request),
        )

        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs) -> Response:
        """Delete user account."""

        # 1. Get target user
        instance = self.get_object()

        # 2. Prevent admin from deleting themselves
        try:
            validate_not_self_action(request.user, instance, "delete")
        except AdminUserActionError as e:
            auth_logger.error(
                "Admin attempted to delete self: admin=%s, IP=%s",
                request.user.email,
                get_client_ip(request),
            )
            return Response({"detail": e.message}, status=e.status_code)

        # 3. Delete user
        self.perform_destroy(instance)

        # 4. Return response with success
        auth_logger.info(
            "Admin deleted user: admin=%s, deleted_user=%s (id=%d), IP=%s",
            request.user.email,
            instance.email,
            instance.id,
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
    Resets password for specified user.
    """

    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = AdminPasswordResetSerializer

    def post(self, request, pk) -> Response:
        """Reset password for specified user."""

        # 1. Get target user by ID
        try:
            user = get_user_by_id_or_raise(pk)
        except UserAccount.DoesNotExist:  # pylint: disable=no-member
            auth_logger.warning(
                "Admin password reset failed: admin=%s, target_user=%s, IP=%s, msg=%s",
                request.user.email,
                pk,
                get_client_ip(request),
                "User not found",
            )
            return Response(
                {"detail": "Пользователь не найден."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # 2. Prevent admin from resetting their own password via this endpoint
        try:
            validate_not_self_action(request.user, user, "password_reset")
        except AdminUserActionError as e:
            auth_logger.error(
                "Admin attempted to reset self password: admin=%s, IP=%s",
                request.user.email,
                get_client_ip(request),
            )
            return Response({"detail": e.message}, status=e.status_code)

        # 3. Validate password reset data via serializer
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

        # 4. Set new password
        new_password = serializer.validated_data["new_password"]
        reset_user_password(user, new_password)

        # 5. Return response with success message
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
    Toggles admin status for specified user.
    """

    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = AdminToggleAdminSerializer

    def post(self, request, pk) -> Response:
        """Toggle admin status for specified user."""

        # 1. Get target user by ID
        try:
            target_user = get_user_by_id_or_raise(pk)
        except UserAccount.DoesNotExist:  # pylint: disable=no-member
            auth_logger.warning(
                "Admin toggle admin status failed: admin=%s, target_user=%s, IP=%s, msg=%s",
                request.user.email,
                pk,
                get_client_ip(request),
                "User not found",
            )
            return Response(
                {"detail": "Пользователь не найден."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # 2. Prevent admin from removing their own admin status
        try:
            validate_not_self_action(request.user, target_user, "toggle_admin")
        except AdminUserActionError as e:
            auth_logger.error(
                "Admin attempted to remove self admin status: admin=%s, IP=%s",
                request.user.email,
                get_client_ip(request),
            )
            return Response({"detail": e.message}, status=e.status_code)

        # 3. Validating the input data via serializer
        serializer = AdminToggleAdminSerializer(data=request.data)
        if not serializer.is_valid():
            auth_logger.warning(
                "Admin toggle admin status failed: admin=%s, target_user=%s, errors=%s, IP=%s",
                request.user.email,
                target_user.email,
                serializer.errors,
                get_client_ip(request),
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # 4. Update admin status
        new_is_admin = serializer.validated_data["is_admin"]
        toggle_admin_status(target_user, new_is_admin)

        # 5. Return response with success message
        auth_logger.info(
            "Admin toggled user admin status: admin=%s, target_user=%s, new_status=%s, IP=%s",
            request.user.email,
            target_user.email,
            target_user.is_staff,
            get_client_ip(request),
        )

        return Response(
            {
                "detail": "Статус администратора успешно изменён.",
                "is_admin": target_user.is_staff,
            },
            status=status.HTTP_200_OK,
        )


class AdminUserStorageStatsView(APIView):
    """
    API endpoint for getting detailed user storage statistics.

    `GET /api/admin/users/{id}/storage-stats/`
    Gets storage statistics for specified user.
    """

    permission_classes = [permissions.IsAuthenticated, IsAdminUser]

    def get(self, request, pk) -> Response:
        """Get storage statistics for specified user."""

        # 1. Get target user by ID
        try:
            user = get_user_by_id_or_raise(pk)
        except UserAccount.DoesNotExist:  # pylint: disable=no-member
            auth_logger.warning(
                "Admin get user storage stats failed: admin=%s, target_user=%s, IP=%s, msg=%s",
                request.user.email,
                pk,
                get_client_ip(request),
                "User not found",
            )
            return Response(
                {"detail": "Пользователь не найден."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # 2. Get storage statistics
        storage_stats = calculate_storage_stats(user)

        stats = {
            "user": {
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
            },
            "storage": {
                "path": user.storage_path,
                **storage_stats,
            },
        }

        # 3. Return storage statistics
        logger.info(
            "Admin accessed user storage stats: admin=%s, target_user=%s, IP=%s",
            request.user.email,
            user.email,
            get_client_ip(request),
        )

        return Response(stats, status=status.HTTP_200_OK)
