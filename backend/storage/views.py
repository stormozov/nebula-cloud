"""
Views for file storage operations.

This module provides API endpoints for:
- File listing (own and admin access)
- File upload
- File deletion
- File rename
- File comment management
- Public link generation/deletion
- File download (authenticated and public)
"""

from django.http import FileResponse
from rest_framework import generics, permissions, status, views
from rest_framework.exceptions import NotFound
from rest_framework.response import Response

from utils.ip_utils import get_client_ip

from .logging import file_logger, logger
from .models import File
from .permissions import IsOwnerOrAdmin
from .serializers import (
    FileCommentSerializer,
    FileRenameSerializer,
    FileSerializer,
    FileUploadSerializer,
    PublicFileSerializer,
)

# ==============================================================================
# FILE LIST AND MANAGEMENT
# ==============================================================================


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
                    logger.info(
                        "Admin %s requested files for user_id=%s, IP=%s",
                        user.email,
                        user_id,
                        get_client_ip(self.request),
                    )
                except (ValueError, TypeError):
                    logger.warning(
                        "Admin %s provided invalid user_id parameter, IP=%s",
                        user.email,
                        get_client_ip(self.request),
                    )
                    queryset = File.objects.filter(owner=user)
            else:
                queryset = File.objects.all()
                logger.info(
                    "Admin %s requested all files, IP=%s",
                    user.email,
                    get_client_ip(self.request),
                )
        else:
            queryset = File.objects.filter(owner=user)
            logger.info(
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

        logger.info(
            "File list retrieved: count=%d, user=%s, IP=%s",
            queryset.count(),
            request.user.email,
            get_client_ip(request),
        )

        return Response(serializer.data)


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

        logger.info(
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
            instance.delete()  # Calls custom model method with file deletion

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


# ==============================================================================
# FILE OPERATIONS (RENAME, COMMENT)
# ==============================================================================


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

            logger.info(
                "File renamed: id=%d, new_name=%s, user=%s, IP=%s",
                file_obj.id,
                file_obj.original_name,
                request.user.email,
                get_client_ip(request),
            )

            response_serializer = FileSerializer(file_obj, context={"request": request})
            return Response(response_serializer.data)

        except File.DoesNotExist:
            logger.warning(
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

            action_type = "updated" if file_obj.comment else "cleared"
            logger.info(
                "Comment %s: id=%d, name=%s, user=%s, IP=%s",
                action_type,
                file_obj.id,
                file_obj.original_name,
                request.user.email,
                get_client_ip(request),
            )

            response_serializer = FileSerializer(file_obj, context={"request": request})
            return Response(response_serializer.data)

        except File.DoesNotExist:
            logger.warning(
                "Comment update failed - not found: id=%s, user=%s, IP=%s",
                pk,
                request.user.email,
                get_client_ip(request),
            )
            raise NotFound("Файл не найден") from None


# ==============================================================================
# PUBLIC LINK MANAGEMENT
# ==============================================================================


class FilePublicLinkView(views.APIView):
    """
    API endpoint for public link management.

    `POST /api/storage/files/{id}/public-link/generate/`
    Generates new public link for file.

    `DELETE /api/storage/files/{id}/public-link/`
    Deletes existing public link.
    """

    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]

    def post(self, request, pk=None) -> Response:
        """
        Generate public link.

        Returns:
            Response: Updated file data with public link.
        """
        try:
            file_obj = File.objects.get(pk=pk)
            self.check_object_permissions(request, file_obj)

            if file_obj.public_link:
                logger.warning(
                    "Public link already exists: id=%d, user=%s, IP=%s",
                    file_obj.id,
                    request.user.email,
                    get_client_ip(request),
                )
                return Response(
                    {
                        "detail": "Публичная ссылка уже существует",
                        "public_link": file_obj.public_link,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            file_obj.generate_public_link(force=True)

            logger.info(
                "Public link generated: id=%d, link=%s, name=%s, user=%s, IP=%s",
                file_obj.id,
                file_obj.public_link,
                file_obj.original_name,
                request.user.email,
                get_client_ip(request),
            )

            response_serializer = FileSerializer(file_obj, context={"request": request})
            return Response(response_serializer.data)

        except File.DoesNotExist:
            logger.warning(
                "Public link generation failed - not found: id=%s, user=%s, IP=%s",
                pk,
                request.user.email,
                get_client_ip(request),
            )
            raise NotFound("Файл не найден") from None

    def delete(self, request, pk=None) -> Response:
        """
        Delete public link.

        Returns:
            Response: Updated file data without public link.
        """
        try:
            file_obj = File.objects.get(pk=pk)
            self.check_object_permissions(request, file_obj)

            if not file_obj.public_link:
                logger.warning(
                    "Public link deletion failed - not exists: id=%d, user=%s, IP=%s",
                    file_obj.id,
                    request.user.email,
                    get_client_ip(request),
                )
                return Response(
                    {"detail": "Публичная ссылка отсутствует"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            old_link = file_obj.public_link
            file_obj.public_link = None
            file_obj.save(update_fields=["public_link"])

            logger.info(
                "Public link deleted: id=%d, link=%s, name=%s, user=%s, IP=%s",
                file_obj.id,
                old_link,
                file_obj.original_name,
                request.user.email,
                get_client_ip(request),
            )

            response_serializer = FileSerializer(file_obj, context={"request": request})
            return Response(response_serializer.data)

        except File.DoesNotExist:
            logger.warning(
                "Public link deletion failed - not found: id=%s, user=%s, IP=%s",
                pk,
                request.user.email,
                get_client_ip(request),
            )
            raise NotFound("Файл не найден") from None


# ==============================================================================
# FILE DOWNLOAD (AUTHENTICATED)
# ==============================================================================


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


# ==============================================================================
# PUBLIC FILE ACCESS
# ==============================================================================


class PublicFileView(views.APIView):
    """
    API endpoint for public file access via public_link.

    `GET /api/storage/public/{public_link}/`
    Returns file information (preview before download).

    `GET /api/storage/public/{public_link}/download/`
    Downloads file without authentication.
    """

    permission_classes = [permissions.AllowAny]

    def get(self, request, public_link=None) -> Response:
        """
        Get public file information.

        Returns:
            Response: Serialized file data for public access.
        """
        try:
            file_obj = File.objects.select_related("owner").get(public_link=public_link)

            logger.info(
                "Public file preview accessed: link=%s, name=%s, IP=%s",
                public_link,
                file_obj.original_name,
                get_client_ip(request),
            )

            serializer = PublicFileSerializer(file_obj, context={"request": request})
            return Response(serializer.data)

        except File.DoesNotExist:
            logger.warning(
                "Public link not found: link=%s, IP=%s",
                public_link,
                get_client_ip(request),
            )
            raise NotFound("Ссылка недействительна или файл удалён") from None


class PublicFileDownloadView(views.APIView):
    """
    API endpoint for public file download.

    `GET /api/storage/public/{public_link}/download/`
    Downloads file via public link without authentication.
    """

    permission_classes = [permissions.AllowAny]

    def get(self, request, public_link=None) -> FileResponse:
        """
        Handle public file download.

        Returns:
            FileResponse: File with original name in Content-Disposition header.
        """
        try:
            file_obj = File.objects.get(public_link=public_link)

            if not file_obj.file or not file_obj.file.storage.exists(file_obj.file.name):
                file_logger.error(
                    "Public file not found on disk: link=%s, path=%s, IP=%s",
                    public_link,
                    file_obj.file.name if file_obj.file else "None",
                    get_client_ip(request),
                )
                raise NotFound("Файл не найден на сервере")

            # Update last download timestamp
            file_obj.update_last_downloaded()

            file_logger.info(
                "Public file downloaded: link=%s, name=%s, size=%d bytes, IP=%s",
                public_link,
                file_obj.original_name,
                file_obj.size,
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
                "Public download failed - not found: link=%s, IP=%s",
                public_link,
                get_client_ip(request),
            )
            raise NotFound("Ссылка недействительна или файл удалён") from None
