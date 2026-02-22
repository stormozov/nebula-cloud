"""
Views for authenticated file operations (CRUD + management).

All views in this module require authentication and appropriate permissions.

The module provides the following views:
- FileListView
- FileUploadView
- FileDetailView
- FileRenameView
- FileCommentView
"""

from django.http import FileResponse
from rest_framework import generics, permissions, status, views
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


class FileListView(generics.ListAPIView):
    """
    API endpoint for file listing.

    `GET /api/storage/files/`
    Returns list of files for authenticated user.

    `GET /api/storage/files/?user_id={id}`
    Admin-only: returns files for specific user.
    """

    serializer_class = FileSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]

    def get_queryset(self) -> File.objects:
        """
        Filter files based on user role.

        Returns:
            QuerySet: Filtered file queryset.
        """

        user = self.request.user

        if user.is_staff:
            user_id = self.request.query_params.get("user_id")
            if user_id:
                try:
                    queryset = File.objects.filter(owner_id=int(user_id))
                    file_logger.info(
                        "Admin %s requested files for user_id=%s, IP=%s",
                        user.email,
                        user_id,
                        get_client_ip(self.request),
                    )
                except (ValueError, TypeError):
                    file_logger.warning(
                        "Admin %s provided invalid user_id parameter, IP=%s",
                        user.email,
                        get_client_ip(self.request),
                    )
                    queryset = File.objects.filter(owner=user)
            else:
                queryset = File.objects.all()
                file_logger.info(
                    "Admin %s requested all files, IP=%s",
                    user.email,
                    get_client_ip(self.request),
                )
        else:
            queryset = File.objects.filter(owner=user)
            file_logger.info(
                "User %s requested own files, IP=%s",
                user.email,
                get_client_ip(self.request),
            )

        return queryset.select_related("owner").order_by("-uploaded_at")

    def list(self, request, *args, **kwargs) -> Response:
        """
        Get list of files.

        Returns:
            Response: Serialized file list.
        """

        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True, context={"request": request})

        file_logger.info(
            "File list retrieved: count=%d, user=%s, IP=%s",
            queryset.count(),
            request.user.email,
            get_client_ip(request),
        )

        return Response(serializer.data)


class FileDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    API endpoint for file detail operations.

    `GET /api/storage/files/{id}/`
    Returns file details.

    `PATCH /api/storage/files/{id}/`
    Updates file metadata.

    `DELETE /api/storage/files/{id}/`
    Deletes file from storage.
    """

    queryset = File.objects.select_related("owner").all()
    serializer_class = FileSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]

    def retrieve(self, request, *args, **kwargs) -> Response:
        """
        Get file details.

        Returns:
            Response: Serialized file data.
        """

        instance = self.get_object()
        serializer = self.get_serializer(instance, context={"request": request})

        file_logger.info(
            "File detail retrieved: id=%d, name=%s, user=%s, IP=%s",
            instance.id,
            instance.original_name,
            request.user.email,
            get_client_ip(request),
        )

        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs) -> Response:
        """
        Delete file.

        Returns:
            Response: No content on success.
        """

        instance = self.get_object()
        filename = instance.original_name
        owner_email = instance.owner.email

        try:
            instance.delete()

            file_logger.info(
                "File deleted: name=%s, id=%d, user=%s, owner=%s, IP=%s",
                filename,
                instance.id,
                request.user.email,
                owner_email,
                get_client_ip(request),
            )

            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            file_logger.error(
                "File deletion failed: id=%d, user=%s, error=%s, IP=%s",
                instance.id,
                request.user.email,
                str(e),
                get_client_ip(request),
            )
            raise


class FileUploadView(generics.CreateAPIView):
    """
    API endpoint for file upload.

    `POST /api/storage/files/upload/`
    Uploads new file with optional comment.
    """

    serializer_class = FileUploadSerializer
    permission_classes = [permissions.IsAuthenticated]

    def create(self, request, *args, **kwargs) -> Response:
        """
        Handle file upload.

        Returns:
            Response: Serialized file data on success.
        """

        serializer = self.get_serializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        try:
            # Set owner from request
            file_obj = serializer.save(owner=request.user)

            file_logger.info(
                "File uploaded: name=%s, size=%d bytes, user=%s, IP=%s",
                file_obj.original_name,
                file_obj.size,
                request.user.email,
                get_client_ip(request),
            )

            response_serializer = FileSerializer(file_obj, context={"request": request})
            return Response(response_serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            file_logger.error(
                "File upload failed: user=%s, error=%s, IP=%s",
                request.user.email,
                str(e),
                get_client_ip(request),
            )
            raise


class FileDownloadView(views.APIView):
    """
    API endpoint for authenticated file download.

    `GET /api/storage/files/{id}/download/`
    Downloads file with original name preservation.
    """

    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]

    def get(self, request, pk=None) -> FileResponse:
        """
        Handle file download.

        Returns:
            FileResponse: File with original name in Content-Disposition header.
        """
        try:
            file_obj = File.objects.get(pk=pk)
            self.check_object_permissions(request, file_obj)

            if not file_obj.file or not file_obj.file.storage.exists(file_obj.file.name):
                file_logger.error(
                    "File not found on disk: id=%d, path=%s, user=%s, IP=%s",
                    file_obj.id,
                    file_obj.file.name if file_obj.file else "None",
                    request.user.email,
                    get_client_ip(request),
                )
                raise NotFound("Файл не найден на сервере")

            # Update last download timestamp
            file_obj.update_last_downloaded()

            file_logger.info(
                "File downloaded: id=%d, name=%s, size=%d bytes, user=%s, owner=%s, IP=%s",
                file_obj.id,
                file_obj.original_name,
                file_obj.size,
                request.user.email,
                file_obj.owner.email,
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
        except File.DoesNotExist:
            file_logger.warning(
                "Download failed - not found: id=%s, user=%s, IP=%s",
                pk,
                request.user.email,
                get_client_ip(request),
            )
            raise NotFound("Файл не найден") from None


class FileRenameView(views.APIView):
    """
    API endpoint for file rename.

    `PATCH /api/storage/files/{id}/rename/`
    Changes original_name of the file.
    """

    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]

    def patch(self, request, pk=None) -> Response:
        """
        Handle file rename.

        Returns:
            Response: Updated file data on success.
        """
        try:
            file_obj = File.objects.get(pk=pk)
            self.check_object_permissions(request, file_obj)

            serializer = FileRenameSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.update(file_obj, serializer.validated_data)

            response_serializer = FileSerializer(file_obj, context={"request": request})

            file_logger.info(
                "File renamed: id=%d, new_name=%s, user=%s, IP=%s",
                file_obj.id,
                file_obj.original_name,
                request.user.email,
                get_client_ip(request),
            )

            return Response(response_serializer.data)
        except File.DoesNotExist:
            file_logger.warning(
                "File rename failed - not found: id=%s, user=%s, IP=%s",
                pk,
                request.user.email,
                get_client_ip(request),
            )
            raise NotFound("Файл не найден") from None


class FileCommentView(views.APIView):
    """
    API endpoint for file comment management.

    `PATCH /api/storage/files/{id}/comment/`
    Updates or clears file comment.
    """

    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]

    def patch(self, request, pk=None) -> Response:
        """
        Handle comment update.

        Returns:
            Response: Updated file data on success.
        """
        try:
            file_obj = File.objects.get(pk=pk)
            self.check_object_permissions(request, file_obj)

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
                request.user.email,
                get_client_ip(request),
            )

            return Response(response_serializer.data)
        except File.DoesNotExist:
            file_logger.warning(
                "Comment update failed - not found: id=%s, user=%s, IP=%s",
                pk,
                request.user.email,
                get_client_ip(request),
            )
            raise NotFound("Файл не найден") from None
