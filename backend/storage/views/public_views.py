"""
Views for public file access via public_link.

These views do not require authentication and are accessible via generated
public links. The module provides the following views:

- PublicFileView: Preview file metadata via public link
- PublicFileDownloadView: Download file via public link without authentication

Note: Public link management (generate/delete) is handled by FileViewSet
@action endpoints since they require authentication.
"""

from django.http import FileResponse
from rest_framework import permissions, views
from rest_framework.exceptions import NotFound
from rest_framework.response import Response

from core.utils import get_client_ip
from storage.loggers import file_logger
from storage.models import File
from storage.serializers import PublicFileSerializer


class PublicFileView(views.APIView):
    """
    API endpoint for public file access via public_link.

    Provides read-only access to file metadata without authentication.
    Used for preview before download in public sharing scenarios.

    Endpoints:
        GET /api/storage/public/{public_link}/ - File metadata preview

    Permissions:
        AllowAny - No authentication required

    Security:
        - Only minimal metadata exposed (no owner info, no internal paths)
        - Public link is unguessable (UUID-based)
        - File must have active public_link to be accessible
    """

    serializer_class = None
    permission_classes = [permissions.AllowAny]

    def get(self, request, public_link: str | None = None) -> Response:
        """
        Retrieve public file information for preview.

        Args:
            request: The HTTP request object.
            public_link: Public link UUID string from URL.

        Returns:
            Response: Serialized file metadata for public access.

        Raises:
            NotFound: If public link is invalid or file was deleted.

        Logs:
            Info: Successful public preview access.
            Warning: Invalid or expired public link access attempt.
        """
        if not public_link:
            file_logger.warning(
                "Public link access attempt with empty link, IP=%s",
                get_client_ip(request),
            )
            raise NotFound("Ссылка недействительна или файл удалён")

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
    API endpoint for public file download via public_link.

    Allows downloading files without authentication using generated public links.
    Updates last_downloaded timestamp for analytics.

    Endpoints:
        GET /api/storage/public/{public_link}/download/ - File download

    Permissions:
        AllowAny - No authentication required

    Security:
        - File served with original name in Content-Disposition header
        - Public link can be revoked by owner at any time
        - Access logged for audit purposes
    """

    serializer_class = None
    permission_classes = [permissions.AllowAny]

    def get(self, request, public_link: str | None = None) -> FileResponse:
        """
        Handle public file download.

        Args:
            request: The HTTP request object.
            public_link: Public link UUID string from URL.

        Returns:
            FileResponse: File content with original name in header.

        Raises:
            NotFound: If public link is invalid or file missing from disk.

        Logs:
            Info: Successful public download with file size.
            Warning: Invalid public link access attempt.
            Error: File missing from disk storage.
        """
        if not public_link:
            file_logger.warning(
                "Public download attempt with empty link, IP=%s",
                get_client_ip(request),
            )
            raise NotFound("Ссылка недействительна или файл удалён")

        try:
            file_obj = File.objects.get(public_link=public_link)

            # Проверка наличия файла на диске
            if not file_obj.file or not file_obj.file.storage.exists(file_obj.file.name):
                file_logger.error(
                    "Public file not found on disk: link=%s, path=%s, IP=%s",
                    public_link,
                    file_obj.file.name if file_obj.file else "None",
                    get_client_ip(request),
                )
                raise NotFound("Файл не найден на сервере")

            # Обновление timestamp последнего скачивания
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
