"""
ViewSet for current user profile management.

This module provides a unified ViewSet for managing the authenticated user's
own profile. All endpoints require authentication and operate on the
current user (request.user), not on arbitrary user IDs.

Endpoints:
    GET    /api/users/me/                    - Get current user profile
    PUT    /api/users/me/                    - Full update profile
    PATCH  /api/users/me/                    - Partial update profile
    POST   /api/users/me/password/           - Change password
    GET    /api/users/me/storage-summary/    - Get storage statistics
    GET    /api/users/me/session-info/       - Get current session details
    POST   /api/users/me/deactivate/         - Deactivate own account

All actions require authentication. Admin-specific operations are handled
separately in AdminUserViewSet.
"""

from django.contrib.auth import update_session_auth_hash
from rest_framework import mixins, permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.request import Request
from rest_framework.response import Response

from core.utils import get_client_ip
from users.loggers import auth_logger, logger
from users.models import UserAccount
from users.serializers import (
    PasswordChangeSerializer,
    UserSerializer,
)
from users.services import calculate_storage_stats


class CurrentUserView(mixins.RetrieveModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """
    ViewSet for managing the current authenticated user's profile.

    Provides endpoints for profile management, password change, storage
    statistics, and account deactivation. All operations are scoped to
    the authenticated user (request.user) - no user ID parameter is needed.

    Attributes:
        serializer_class: Default serializer for profile operations.
        permission_classes: Requires authentication for all endpoints.

    Security Notes:
        - All endpoints require valid JWT token in Authorization header
        - Password change invalidates existing sessions for security
        - Account deactivation is irreversible (requires admin to restore)
    """

    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = UserAccount.objects.none()  # type: ignore

    def get_object(self) -> UserAccount:
        """
        Return the current authenticated user.

        Overrides default get_object() to always return request.user
        instead of looking up by PK. This ensures users can only
        access their own profile data.

        Returns:
            UserAccount: The currently authenticated user instance.

        Raises:
            PermissionDenied: If user is not authenticated (handled by
            permission_classes before this method is called).
        """
        return self.request.user

    def _get_user_email_for_log(self) -> str:
        """
        Safely get current user email for logging.

        Returns:
            str: User email or 'anonymous' if not authenticated.
        """
        user = self.request.user
        return getattr(user, "email", "anonymous") if user else "anonymous"

    # ==============================================================================================
    # STANDARD ACTIONS (retrieve, update, partial_update)
    # ==============================================================================================

    def retrieve(self, request: Request, *args, **kwargs) -> Response:
        """
        Retrieve current user profile data.

        Returns user profile information including id, username, email,
        first_name, last_name, and storage_path. Does not include sensitive
        data like password or session tokens.

        Args:
            request: The HTTP request object with authentication.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: 200 OK with user profile data.

        Endpoint:
            GET /api/users/me/

        Example Response:
            {
                "id": 1,
                "username": "john_doe",
                "email": "john@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "storage_path": "/storage/user_1/"
            }
        """

        instance = self.get_object()
        serializer = self.get_serializer(instance, context={"request": request})

        logger.info(
            "User profile accessed: email=%s, IP=%s",
            self._get_user_email_for_log(),
            get_client_ip(request),
        )

        return Response(serializer.data)

    def update(self, request: Request, *args, **kwargs) -> Response:
        """
        Fully update current user profile.

        Allows updating first_name and last_name. Email and username
        cannot be changed through this endpoint for security reasons.

        Args:
            request: The HTTP request object with update data.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: 200 OK with updated user profile data.
            Response: 400 Bad Request if validation fails.

        Endpoint:
            PUT /api/users/me/

        Request Body:
            {
                "first_name": "John",
                "last_name": "Doe"
            }

        Notes:
            - Email changes require separate verification flow
            - Username changes are not allowed after registration
        """

        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        logger.info(
            "User profile updated: email=%s, updated_fields=%s, IP=%s",
            self._get_user_email_for_log(),
            list(request.data.keys()),
            get_client_ip(request),
        )

        return Response(serializer.data)

    def partial_update(self, request: Request, *args, **kwargs) -> Response:
        """
        Partially update current user profile.

        Same as update() but allows sending only fields that need changes.
        Recommended for frontend forms with individual field updates.

        Args:
            request: The HTTP request object with update data.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: 200 OK with updated user profile data.

        Endpoint:
            PATCH /api/users/me/

        Example:
            PATCH /api/users/me/
            { "first_name": "Jane" }
        """
        kwargs["partial"] = True
        return self.update(request, *args, **kwargs)

    # ==============================================================================================
    # CUSTOM ACTIONS
    # ==============================================================================================

    @action(detail=False, methods=["post"], url_path="password")
    def change_password(self, request: Request, *args, **kwargs) -> Response:
        """
        Change the authenticated user's password.

        Requires current password for verification. On success, updates
        password and invalidates existing sessions for security.

        Args:
            request: The HTTP request object with password change data.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: 200 OK with success message.
            Response: 400 Bad Request if validation fails.

        Endpoint:
            POST /api/users/me/password/

        Request Body:
            {
                "current_password": "OldPass123!",
                "new_password": "NewSecurePass456!",
                "new_password_confirm": "NewSecurePass456!"
            }

        Security Notes:
            - Current password must be correct
            - New password must meet validation requirements
            - All existing sessions are invalidated after change
            - User must re-login with new password
        """

        # 1. Validate data via serializer
        serializer = PasswordChangeSerializer(data=request.data, context={"request": request})

        if not serializer.is_valid():
            auth_logger.warning(
                "Failed password change attempt: user=%s, errors=%s, IP=%s",
                self._get_user_email_for_log(),
                serializer.errors,
                get_client_ip(request),
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # 2. Update password
        user = request.user
        new_password: str = serializer.validated_data["new_password"]
        user.set_password(new_password)
        user.save()

        # 3. Invalidate existing sessions (security best practice)
        update_session_auth_hash(request, user)

        # 4. Log success
        auth_logger.info(
            "User password changed successfully: email=%s, username=%s, IP=%s",
            user.email,
            user.username,
            get_client_ip(request),
        )

        return Response({"detail": "Пароль успешно изменён."}, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"], url_path="storage-summary")
    def storage_summary(self, request: Request, *args, **kwargs) -> Response:
        """
        Get storage statistics for the current user.

        Returns file count, total size, and formatted size for dashboard
        display. Useful for showing storage usage without full file list.

        Args:
            request: The HTTP request object with authentication.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: 200 OK with storage statistics.

        Endpoint:
            GET /api/users/me/storage-summary/

        Example Response:
            {
                "file_count": 42,
                "total_size": 1073741824,
                "total_size_formatted": "1 GB",
                "storage_path": "/storage/user_1/"
            }
        """

        user = request.user
        storage_stats = calculate_storage_stats(user)

        stats = {
            "file_count": storage_stats["file_count"],
            "total_size": storage_stats["total_size"],
            "total_size_formatted": storage_stats["total_size_formatted"],
            "storage_path": user.storage_path,
        }

        logger.info(
            "User storage summary accessed: email=%s, files=%d, size=%d, IP=%s",
            self._get_user_email_for_log(),
            stats["file_count"],
            stats["total_size"],
            get_client_ip(request),
        )

        return Response(stats, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"], url_path="session-info")
    def session_info(self, request: Request, *args, **kwargs) -> Response:
        """
        Get current session information.

        Returns details about the current authenticated session including
        client IP, user agent, and session metadata. Useful for security
        monitoring and "active sessions" UI.

        Args:
            request: The HTTP request object with authentication.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: 200 OK with session details.

        Endpoint:
            GET /api/users/me/session-info/

        Example Response:
            {
                "user_id": 1,
                "username": "john_doe",
                "email": "john@example.com",
                "client_ip": "192.168.1.1",
                "user_agent": "Mozilla/5.0...",
                "is_staff": false
            }
        """

        user = request.user
        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "unknown")

        session_data = {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "is_staff": user.is_staff,
            "is_active": user.is_active,
        }

        logger.debug(
            "Session info accessed: email=%s, IP=%s, user_agent=%s",
            self._get_user_email_for_log(),
            client_ip,
            user_agent[:50],
        )

        return Response(session_data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], url_path="deactivate")
    def deactivate_account(self, request: Request, *args, **kwargs) -> Response:
        """
        Deactivate the current user's own account.

        Sets is_active=False, effectively logging out the user and
        preventing future logins. This action is irreversible without
        admin intervention.

        Args:
            request: The HTTP request object with authentication.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: 200 OK with success message.

        Endpoint:
            POST /api/users/me/deactivate/

        Security Notes:
            - This action is irreversible by the user
            - All sessions are invalidated immediately
            - Admin can restore account if needed
            - User data and files are preserved (not deleted)
        """

        user = request.user
        user_email = user.email
        user_id = user.id

        # Deactivate account
        user.is_active = False
        user.save(update_fields=["is_active"])

        auth_logger.info(
            "User deactivated own account: email=%s, user_id=%d, IP=%s",
            user_email,
            user_id,
            get_client_ip(request),
        )

        return Response(
            {
                "detail": "Ваш аккаунт был деактивирован.",
                "message": "Обратитесь к администратору для восстановления.",
            },
            status=status.HTTP_200_OK,
        )
