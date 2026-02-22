"""
Views for public file access via public_link.

These views do not require authentication and are accessible via generated public links.

The module provides the following views:
- FilePublicLinkView
- PublicFileView
- PublicFileDownloadView

"""

from django.http import FileResponse
from rest_framework import permissions, status, views
from rest_framework.exceptions import NotFound
from rest_framework.response import Response

from core.utils import get_client_ip
from storage.loggers import file_logger
from storage.models import File
from storage.permissions import IsOwnerOrAdmin
from storage.serializers import FileSerializer, PublicFileSerializer


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
                file_logger.warning(
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

            file_logger.info(
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
            file_logger.warning(
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
                file_logger.warning(
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

            file_logger.info(
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
            file_logger.warning(
                "Public link deletion failed - not found: id=%s, user=%s, IP=%s",
                pk,
                request.user.email,
                get_client_ip(request),
            )
            raise NotFound("Файл не найден") from None


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
            serializer = PublicFileSerializer(file_obj, context={"request": request})

            file_logger.info(
                "Public file preview accessed: link=%s, name=%s, IP=%s",
                public_link,
                file_obj.original_name,
                get_client_ip(request),
            )

            return Response(serializer.data)
        except File.DoesNotExist:
            file_logger.warning(
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
