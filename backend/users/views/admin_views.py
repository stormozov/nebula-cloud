"""
ViewSet for admin user management.
This module provides a unified ViewSet for managing users with admin privileges.
All actions require authentication and admin status.
"""

from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from core.utils import get_client_ip
from users.exceptions import AdminUserActionError
from users.loggers import auth_logger, logger
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


class AdminUserViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing users with admin privileges.

    Provides CRUD operations for user accounts plus custom actions for
    password reset, admin status toggle, and storage statistics.
    All endpoints require authentication and admin status.

    Attributes:
        queryset: All UserAccount objects.
        permission_classes: Requires authentication and admin status.
        serializer_class: Default serializer for list/retrieve operations.

    Endpoints:
        GET    /api/admin/users/              - List all users
        GET    /api/admin/users/{id}/         - Get user details
        PUT    /api/admin/users/{id}/         - Update user data
        DELETE /api/admin/users/{id}/         - Delete user
        POST   /api/admin/users/{id}/password/ - Reset user password
        POST   /api/admin/users/{id}/toggle-admin/ - Toggle admin status
        GET    /api/admin/users/{id}/storage-stats/ - Get storage statistics
        GET    /api/admin/users/{id}/export/ - Export user data
    """

    queryset = UserAccount.objects.all().order_by("username")
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]

    def get_serializer_class(self) -> type:
        """
        Return appropriate serializer based on request method and action.

        Different serializers are used for different operations:
        - AdminUserListSerializer: for listing users (lightweight)
        - AdminUserDetailSerializer: for retrieving user details
        - AdminUserUpdateSerializer: for updating user data

        Returns:
            type: Serializer class for current action.
        """

        if self.action == "list":
            return AdminUserListSerializer
        if self.action in ["update", "partial_update"]:
            return AdminUserUpdateSerializer

        return AdminUserDetailSerializer

    def _get_user_email_for_log(self) -> str:
        """
        Safely get admin user email for logging.

        Returns:
            str: Admin user email or 'anonymous' if not authenticated.
        """
        user = self.request.user
        return getattr(user, "email", "anonymous") if user else "anonymous"

    def _get_target_user(self, pk: int) -> UserAccount:
        """
        Get target user by primary key with error handling.

        Args:
            pk: Primary key of the target user.

        Returns:
            UserAccount: The target user instance.

        Raises:
            NotFound: If user with given pk doesn't exist.
        """
        return get_user_by_id_or_raise(pk)

    def list(self, request, *args, **kwargs) -> Response:
        """
        Retrieve a list of all users.

        Returns paginated list of users with basic information and storage
        statistics. Only accessible to admin users.

        Args:
            request: The HTTP request object.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: Paginated list of users with storage stats.

        Endpoint:
            GET /api/admin/users/
        """

        queryset = self.get_queryset()
        total_count = queryset.count()

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True, context={"request": request})
            logger.info(
                "Admin user list retrieved: count=%d (total=%d), admin=%s, IP=%s",
                len(page),
                total_count,
                self._get_user_email_for_log(),
                get_client_ip(request),
            )
            return self.get_paginated_response(serializer.data)

        # if pagination is not configured (PAGE_SIZE = None), return all records
        serializer = self.get_serializer(queryset, many=True, context={"request": request})
        logger.info(
            "Admin user list retrieved: count=%d, admin=%s, IP=%s",
            total_count,
            self._get_user_email_for_log(),
            get_client_ip(request),
        )
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs) -> Response:
        """
        Retrieve details of a specific user.

        Returns detailed user information including storage statistics.

        Args:
            request: The HTTP request object.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments containing user pk.

        Returns:
            Response: User details with storage statistics.

        Endpoint:
            GET /api/admin/users/{id}/
        """

        instance = self.get_object()
        serializer = self.get_serializer(instance, context={"request": request})

        logger.info(
            "Admin accessed user details: admin=%s, target_user=%s, IP=%s",
            self._get_user_email_for_log(),
            instance.email,
            get_client_ip(request),
        )

        return Response(serializer.data)

    def update(self, request, *args, **kwargs) -> Response:
        """
        Fully update a user's data.

        Args:
            request: The HTTP request object containing update data.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments containing user pk.

        Returns:
            Response: Updated user data.

        Endpoint:
            PUT /api/admin/users/{id}/
        """

        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        logger.info(
            "Admin updated user: admin=%s, target_user=%s, fields=%s, IP=%s",
            self._get_user_email_for_log(),
            instance.email,
            list(request.data.keys()),
            get_client_ip(request),
        )

        return Response(serializer.data)

    def partial_update(self, request, *args, **kwargs) -> Response:
        """
        Partially update a user's data.

        Args:
            request: The HTTP request object containing update data.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments containing user pk.

        Returns:
            Response: Updated user data.

        Endpoint:
            PATCH /api/admin/users/{id}/
        """
        kwargs["partial"] = True
        return self.update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs) -> Response:
        """
        Delete a user account.

        Prevents admin from deleting their own account.

        Args:
            request: The HTTP request object.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments containing user pk.

        Returns:
            Response: Success message.

        Raises:
            AdminUserActionError: If admin attempts to delete themselves.

        Endpoint:
            DELETE /api/admin/users/{id}/
        """

        instance = self.get_object()

        try:
            validate_not_self_action(request.user, instance, "delete")
        except AdminUserActionError as e:
            auth_logger.error(
                "Admin attempted to delete self: admin=%s, IP=%s",
                self._get_user_email_for_log(),
                get_client_ip(request),
            )
            return Response({"detail": e.message}, status=e.status_code)

        instance_email = instance.email
        instance_id = instance.id
        self.perform_destroy(instance)

        auth_logger.info(
            "Admin deleted user: admin=%s, deleted_user=%s (id=%d), IP=%s",
            self._get_user_email_for_log(),
            instance_email,
            instance_id,
            get_client_ip(request),
        )

        return Response({"detail": "Пользователь успешно удалён."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"], url_path="password")
    def reset_password(self, request, *args, **kwargs) -> Response:
        """
        Reset password for specified user.

        Admin can reset any user's password except their own.

        Args:
            request: The HTTP request object containing new_password.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments containing user pk.

        Returns:
            Response: Success message.

        Raises:
            AdminUserActionError: If admin attempts to reset their own password.
            NotFound: If user doesn't exist.

        Endpoint:
            POST /api/admin/users/{id}/password/
        """

        try:
            user = self._get_target_user(kwargs["pk"])
        except UserAccount.DoesNotExist:
            auth_logger.warning(
                "Admin password reset failed: admin=%s, target_user=%s, IP=%s, msg=%s",
                self._get_user_email_for_log(),
                kwargs["pk"],
                get_client_ip(request),
                "User not found",
            )
            return Response({"detail": "Пользователь не найден."}, status=status.HTTP_404_NOT_FOUND)

        try:
            validate_not_self_action(request.user, user, "password_reset")
        except AdminUserActionError as e:
            auth_logger.error(
                "Admin attempted to reset self password: admin=%s, IP=%s",
                self._get_user_email_for_log(),
                get_client_ip(request),
            )
            return Response({"detail": e.message}, status=e.status_code)

        serializer = AdminPasswordResetSerializer(data=request.data)
        if not serializer.is_valid():
            auth_logger.warning(
                "Admin password reset failed: admin=%s, target_user=%s, errors=%s, IP=%s",
                self._get_user_email_for_log(),
                user.email,
                serializer.errors,
                get_client_ip(request),
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        new_password = serializer.validated_data["new_password"]
        reset_user_password(user, new_password)

        auth_logger.info(
            "Admin reset user password: admin=%s, target_user=%s, IP=%s",
            self._get_user_email_for_log(),
            user.email,
            get_client_ip(request),
        )

        return Response(
            {"detail": "Пароль пользователя успешно сброшен."}, status=status.HTTP_200_OK
        )

    @action(detail=True, methods=["post"], url_path="toggle-admin")
    def toggle_admin(self, request, *args, **kwargs) -> Response:
        """
        Toggle admin status for specified user.

        Admin can change any user's admin status except their own.

        Args:
            request: The HTTP request object containing is_admin boolean.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments containing user pk.

        Returns:
            Response: Success message with new admin status.

        Raises:
            AdminUserActionError: If admin attempts to remove their own admin status.
            NotFound: If user doesn't exist.

        Endpoint:
            POST /api/admin/users/{id}/toggle-admin/
        """

        try:
            target_user = self._get_target_user(kwargs["pk"])
        except UserAccount.DoesNotExist:
            auth_logger.warning(
                "Admin toggle admin status failed: admin=%s, target_user=%s, IP=%s, msg=%s",
                self._get_user_email_for_log(),
                kwargs["pk"],
                get_client_ip(request),
                "User not found",
            )
            return Response({"detail": "Пользователь не найден."}, status=status.HTTP_404_NOT_FOUND)

        try:
            validate_not_self_action(request.user, target_user, "toggle_admin")
        except AdminUserActionError as e:
            auth_logger.error(
                "Admin attempted to remove self admin status: admin=%s, IP=%s",
                self._get_user_email_for_log(),
                get_client_ip(request),
            )
            return Response({"detail": e.message}, status=e.status_code)

        serializer = AdminToggleAdminSerializer(data=request.data)
        if not serializer.is_valid():
            auth_logger.warning(
                "Admin toggle admin status failed: admin=%s, target_user=%s, errors=%s, IP=%s",
                self._get_user_email_for_log(),
                target_user.email,
                serializer.errors,
                get_client_ip(request),
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        new_is_admin = serializer.validated_data["is_staff"]
        toggle_admin_status(target_user, new_is_admin)

        auth_logger.info(
            "Admin toggled user admin status: admin=%s, target_user=%s, new_status=%s, IP=%s",
            self._get_user_email_for_log(),
            target_user.email,
            target_user.is_staff,
            get_client_ip(request),
        )

        return Response(
            {"detail": "Статус администратора успешно изменён.", "is_staff": target_user.is_staff},
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["get"], url_path="storage-stats")
    def storage_stats(self, request, *args, **kwargs) -> Response:
        """
        Get detailed storage statistics for specified user.

        Returns storage path, file count, and total size.

        Args:
            request: The HTTP request object.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments containing user pk.

        Returns:
            Response: Storage statistics with user info.

        Raises:
            NotFound: If user doesn't exist.

        Endpoint:
            GET /api/admin/users/{id}/storage-stats/
        """

        try:
            user = self._get_target_user(kwargs["pk"])
        except UserAccount.DoesNotExist:
            auth_logger.warning(
                "Admin get user storage stats failed: admin=%s, target_user=%s, IP=%s, msg=%s",
                self._get_user_email_for_log(),
                kwargs["pk"],
                get_client_ip(request),
                "User not found",
            )
            return Response({"detail": "Пользователь не найден."}, status=status.HTTP_404_NOT_FOUND)

        storage_stats = calculate_storage_stats(user)

        stats = {
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
            },
            "storage": {
                "path": user.storage_path,
                **storage_stats,
            },
        }

        logger.info(
            "Admin accessed user storage stats: admin=%s, target_user=%s, IP=%s",
            self._get_user_email_for_log(),
            user.email,
            get_client_ip(request),
        )

        return Response(stats, status=status.HTTP_200_OK)

    @action(detail=True, methods=["get"], url_path="export")
    def export_user_data(self, request, pk=None):
        """Export user data as JSON."""

        user = self.get_object()

        data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.get_full_name(),
            "is_staff": user.is_staff,
            "is_active": user.is_active,
            "date_joined": user.date_joined,
            "last_login": user.last_login,
            "storage_path": user.storage_path,
            "storage_stats": calculate_storage_stats(user),
        }

        return Response(data)
