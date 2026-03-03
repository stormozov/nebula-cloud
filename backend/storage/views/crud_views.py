"""
ViewSet for authenticated file operations (CRUD + management).
All actions in this module require authentication and appropriate permissions.
"""

from django.http import FileResponse
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound
from rest_framework.response import Response

from core.utils import get_client_ip
from storage.loggers import file_logger
from storage.models import File
from storage.permissions import IsOwnerOrAdmin
from storage.serializers import (
    FileCommentSerializer,
    FileRenameSerializer,
    FileSerializer,
    FileUploadSerializer,
)


class FileViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing user files with authentication and permission checks.

    Provides standard CRUD operations plus custom actions for upload, download,
    rename, and comment management. Admin users can access all files; regular
    users can only access their own files.
    """

    serializer_class = FileSerializer
    # Добавляем IsAuthenticated для блокировки анонимных запросов до выполнения логики
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]

    def get_queryset(self):
        """
        Return queryset filtered by owner for list action only.

        For list: filter by owner to prevent ID enumeration attacks.
        For detail actions (retrieve/update/destroy): return full queryset
        and let permission class (IsOwnerOrAdmin) handle access control.
        This ensures 403 (Forbidden) instead of 404 (Not Found) for
        unauthorized access to existing files.
        """
        user = self.request.user

        # Для list-экшена фильтруем по владельцу
        if self.action == "list":
            if user.is_staff:
                user_id = self.request.query_params.get("user_id")
                if user_id:
                    try:
                        queryset = File.objects.filter(
                            owner_id=int(user_id)
                        )  # pylint: disable=no-member
                        user_email = getattr(user, "email", "anonymous")
                        file_logger.info(
                            "Admin %s requested files for user_id=%s, IP=%s",
                            user_email,
                            user_id,
                            get_client_ip(self.request),
                        )
                    except (ValueError, TypeError):
                        user_email = getattr(user, "email", "anonymous")
                        file_logger.warning(
                            "Admin %s provided invalid user_id parameter, IP=%s",
                            user_email,
                            get_client_ip(self.request),
                        )
                        queryset = File.objects.filter(owner=user)  # pylint: disable=no-member
                else:
                    queryset = File.objects.all()  # pylint: disable=no-member
                    user_email = getattr(user, "email", "anonymous")
                    file_logger.info(
                        "Admin %s requested all files, IP=%s",
                        user_email,
                        get_client_ip(self.request),
                    )
            else:
                queryset = File.objects.filter(owner=user)  # pylint: disable=no-member
                user_email = getattr(user, "email", "anonymous")
                file_logger.info(
                    "User %s requested own files, IP=%s",
                    user_email,
                    get_client_ip(self.request),
                )
        else:
            # Для detail-действий не фильтруем — permission класс проверит права
            # и вернёт 403 вместо 404, что безопаснее (не раскрывает существование)
            queryset = File.objects.all()  # pylint: disable=no-member

        return queryset.select_related("owner").order_by("-uploaded_at")

    def get_serializer_class(self):
        """
        Return appropriate serializer based on action.

        FileUploadSerializer: for file upload (create/upload actions) - handles
        extraction of original_name and size from uploaded file.
        FileSerializer: for all other operations (list/retrieve/update/etc).

        Returns:
            type: Serializer class for current action.
        """
        if self.action in ["create", "upload"]:
            return FileUploadSerializer
        return FileSerializer

    def _get_user_email_for_log(self) -> str:
        """
        Safely get user email for logging, handling AnonymousUser.

        Returns:
            str: User email or 'anonymous' if not authenticated.
        """
        user = self.request.user
        return getattr(user, "email", "anonymous") if user else "anonymous"

    def list(self, request, *args, **kwargs):
        """Retrieve a list of files for the authenticated user."""
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True, context={"request": request})

        file_logger.info(
            "File list retrieved: count=%d, user=%s, IP=%s",
            queryset.count(),
            self._get_user_email_for_log(),
            get_client_ip(request),
        )

        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        """Retrieve details of a specific file."""
        instance = self.get_object()
        serializer = self.get_serializer(instance, context={"request": request})

        file_logger.info(
            "File detail retrieved: id=%d, name=%s, user=%s, IP=%s",
            instance.id,
            instance.original_name,
            self._get_user_email_for_log(),
            get_client_ip(request),
        )

        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        """
        Upload a new file to the storage.

        Expects multipart/form-data with 'file' and optional 'comment' fields.
        Uses FileUploadSerializer to extract metadata from uploaded file.
        """
        serializer = self.get_serializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        try:
            file_obj = serializer.save(owner=request.user)

            file_logger.info(
                "File uploaded: name=%s, size=%d bytes, user=%s, IP=%s",
                file_obj.original_name,
                file_obj.size,
                self._get_user_email_for_log(),
                get_client_ip(request),
            )

            # Для ответа используем FileSerializer (read-only, с дополнительными полями)
            response_serializer = FileSerializer(file_obj, context={"request": request})
            return Response(response_serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            file_logger.error(
                "File upload failed: user=%s, error=%s, IP=%s",
                self._get_user_email_for_log(),
                str(e),
                get_client_ip(request),
            )
            return Response(
                {"detail": "Не удалось загрузить файл. Попробуйте позже."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def update(self, request, *args, **kwargs):
        """Fully update a file's metadata."""
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=False)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        file_logger.info(
            "File updated: id=%d, name=%s, user=%s, IP=%s",
            instance.id,
            instance.original_name,
            self._get_user_email_for_log(),
            get_client_ip(request),
        )

        return Response(serializer.data)

    def partial_update(self, request, *args, **kwargs):
        """Partially update a file's metadata."""
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        file_logger.info(
            "File partially updated: id=%d, name=%s, user=%s, IP=%s",
            instance.id,
            instance.original_name,
            self._get_user_email_for_log(),
            get_client_ip(request),
        )

        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        """Delete a file from the storage."""
        instance = self.get_object()
        filename = instance.original_name
        owner_email = getattr(instance.owner, "email", "unknown")

        try:
            instance.delete()

            file_logger.info(
                "File deleted: name=%s, id=%d, user=%s, owner=%s, IP=%s",
                filename,
                instance.id,
                self._get_user_email_for_log(),
                owner_email,
                get_client_ip(request),
            )

            return Response(status=status.HTTP_204_NO_CONTENT)

        except Exception as e:
            file_logger.error(
                "File deletion failed: id=%d, user=%s, error=%s, IP=%s",
                instance.id,
                self._get_user_email_for_log(),
                str(e),
                get_client_ip(request),
            )
            return Response(
                {"detail": "Не удалось удалить файл. Попробуйте позже."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=False, methods=["post"], url_path="upload")
    def upload(self, request, *args, **kwargs):
        """
        Upload a new file with optional comment.

        Alternative endpoint to standard create with explicit upload semantics.
        Functionally equivalent to create() but provides clearer API documentation.
        """
        # get_serializer_class() уже вернёт FileUploadSerializer для action="upload"
        serializer = self.get_serializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        try:
            file_obj = serializer.save(owner=request.user)

            file_logger.info(
                "File uploaded (via upload action): name=%s, size=%d bytes, user=%s, IP=%s",
                file_obj.original_name,
                file_obj.size,
                self._get_user_email_for_log(),
                get_client_ip(request),
            )

            response_serializer = FileSerializer(file_obj, context={"request": request})
            return Response(response_serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            file_logger.error(
                "File upload failed (via upload action): user=%s, error=%s, IP=%s",
                self._get_user_email_for_log(),
                str(e),
                get_client_ip(request),
            )
            return Response(
                {"detail": "Не удалось загрузить файл. Попробуйте позже."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=True, methods=["get"], url_path="download")
    def download(self, request, *args, **kwargs):
        """
        Download a file with original name preservation.

        Updates last_downloaded timestamp on success.
        Returns FileResponse with Content-Disposition header for attachment.
        """
        file_obj = self.get_object()

        # Дополнительная проверка: файл должен иметь сохранённый путь
        if not file_obj.file or not file_obj.file.name:
            file_logger.error(
                "File has no storage path: id=%d, user=%s, IP=%s",
                file_obj.id,
                self._get_user_email_for_log(),
                get_client_ip(request),
            )
            raise NotFound("Файл не сохранён на сервере")

        if not file_obj.file.storage.exists(file_obj.file.name):
            file_logger.error(
                "File not found on disk: id=%d, path=%s, user=%s, IP=%s",
                file_obj.id,
                file_obj.file.name,
                self._get_user_email_for_log(),
                get_client_ip(request),
            )
            raise NotFound("Файл не найден на сервере")

        file_obj.update_last_downloaded()

        file_logger.info(
            "File downloaded: id=%d, name=%s, size=%d bytes, user=%s, owner=%s, IP=%s",
            file_obj.id,
            file_obj.original_name,
            file_obj.size,
            self._get_user_email_for_log(),
            getattr(file_obj.owner, "email", "unknown"),
            get_client_ip(request),
        )

        response = FileResponse(
            file_obj.file.open("rb"),
            content_type="application/octet-stream",
            as_attachment=True,
            filename=file_obj.original_name,
        )
        response["Content-Length"] = file_obj.size
        return response

    @action(detail=True, methods=["patch"], url_path="rename")
    def rename(self, request, *args, **kwargs):
        """Rename a file by updating its original_name field."""
        file_obj = self.get_object()

        serializer = FileRenameSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.update(file_obj, serializer.validated_data)

        response_serializer = FileSerializer(file_obj, context={"request": request})

        file_logger.info(
            "File renamed: id=%d, new_name=%s, user=%s, IP=%s",
            file_obj.id,
            file_obj.original_name,
            self._get_user_email_for_log(),
            get_client_ip(request),
        )

        return Response(response_serializer.data)

    @action(detail=True, methods=["patch"], url_path="comment")
    def comment(self, request, *args, **kwargs):
        """Update or clear a file's comment field."""
        file_obj = self.get_object()

        serializer = FileCommentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.update(file_obj, serializer.validated_data)

        response_serializer = FileSerializer(file_obj, context={"request": request})

        action_type = "updated" if file_obj.comment else "cleared"

        file_logger.info(
            "Comment %s: id=%d, name=%s, user=%s, IP=%s",
            action_type,
            file_obj.id,
            file_obj.original_name,
            self._get_user_email_for_log(),
            get_client_ip(request),
        )

        return Response(response_serializer.data)

    @action(detail=True, methods=["post"], url_path="public-link/generate")
    def generate_public_link(self, request, *args, **kwargs) -> Response:
        """
        Generate a new public link for file sharing.

        Creates an unguessable UUID-based link that allows anonymous access
        to download the file. Existing link is replaced if already exists.

        Args:
            request: The HTTP request object containing user authentication.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments containing file PK.

        Returns:
            Response: Updated file data with new public_link and URL.

        Raises:
            PermissionDenied: If user doesn't own the file (checked by permissions).

        Endpoint:
            POST /api/storage/files/{id}/public-link/generate/

        Logs:
            Info: Successful link generation with new UUID.
            Warning: Link generation for already-linked file (replaced).
        """
        file_obj = self.get_object()

        # Предупреждение если ссылка уже существует (будет заменена)
        if file_obj.public_link:
            old_link = file_obj.public_link
            file_logger.warning(
                "Public link replaced: id=%d, old_link=%s, user=%s, IP=%s",
                file_obj.id,
                old_link,
                self._get_user_email_for_log(),
                get_client_ip(request),
            )

        file_obj.generate_public_link(force=True)

        file_logger.info(
            "Public link generated: id=%d, link=%s, name=%s, user=%s, IP=%s",
            file_obj.id,
            file_obj.public_link,
            file_obj.original_name,
            self._get_user_email_for_log(),
            get_client_ip(request),
        )

        response_serializer = FileSerializer(file_obj, context={"request": request})
        return Response(response_serializer.data)

    @action(detail=True, methods=["delete"], url_path="public-link")
    def delete_public_link(self, request, *args, **kwargs) -> Response:
        """
        Delete existing public link for file.

        Revokes anonymous access to the file. The link becomes invalid
        immediately and cannot be recovered.

        Args:
            request: The HTTP request object containing user authentication.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments containing file PK.

        Returns:
            Response: Updated file data without public_link.

        Raises:
            NotFound: If file doesn't have an active public link.
            PermissionDenied: If user doesn't own the file (checked by permissions).

        Endpoint:
            DELETE /api/storage/files/{id}/public-link/

        Logs:
            Info: Successful link deletion.
            Warning: Attempt to delete non-existent link.
        """
        file_obj = self.get_object()

        if not file_obj.public_link:
            file_logger.warning(
                "Public link deletion failed - not exists: id=%d, user=%s, IP=%s",
                file_obj.id,
                self._get_user_email_for_log(),
                get_client_ip(request),
            )
            return Response(
                {"detail": "Публичная ссылка отсутствует"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        old_link = file_obj.public_link
        file_obj.public_link = None
        file_obj.save(update_fields=["public_link"])

        file_logger.info(
            "Public link deleted: id=%d, link=%s, name=%s, user=%s, IP=%s",
            file_obj.id,
            old_link,
            file_obj.original_name,
            self._get_user_email_for_log(),
            get_client_ip(request),
        )

        response_serializer = FileSerializer(file_obj, context={"request": request})
        return Response(response_serializer.data)
