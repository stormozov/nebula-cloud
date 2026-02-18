"""
Tests for public file access views.

This module tests all public (unauthenticated) file operations including:
- Public link generation (authenticated endpoint)
- Public link deletion (authenticated endpoint)
- Public file info retrieval (unauthenticated)
- Public file download (unauthenticated)
"""

# pylint: disable=no-member

from django.contrib.auth import get_user_model
from rest_framework import status

from storage.models import File

User = get_user_model()


# ==============================================================================
# TESTS: PUBLIC LINK GENERATION
# ==============================================================================


class TestPublicLinkGenerateView:
    """
    Test suite for public link generation endpoint.

    Endpoint: POST /api/storage/files/{id}/public-link/generate/
    Authentication: Required (owner or admin)
    """

    def test_generate_link_owner_returns_200(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that file owner can generate public link.

        Scenario:
            1. Owner sends POST request to generate link
            2. Server generates unique public_link
            3. Response contains updated file data

        Expected:
            - HTTP 200 OK
            - public_link is generated (12 characters)
            - has_public_link is True
            - public_link_url is not None

        Edge Cases:
            - Link is anonymized (no username, path, or original filename)
        """

        # Arrange
        file_obj = create_file(
            owner=authenticated_client.user,
            original_name="secret_document.pdf",
        )

        # Act
        response = authenticated_client.post(
            f"/api/storage/files/{file_obj.id}/public-link/generate/",
            data={},
            format="json",
        )

        # Assert
        assert file_obj.public_link is None
        assert response.status_code == status.HTTP_200_OK
        assert response.data["has_public_link"] is True
        assert response.data["public_link_url"] is not None

        # Verify link is anonymized (no user info in URL)
        assert str(authenticated_client.user.id) not in response.data["public_link_url"]
        assert "secret_document" not in response.data["public_link_url"]

        # Verify link saved to database
        file_obj.refresh_from_db()
        assert file_obj.public_link is not None
        assert len(file_obj.public_link) == 12

    def test_generate_link_unauthorized_returns_401(self, api_client, create_file):
        """
        Verify that unauthenticated user cannot generate public link.

        Expected:
            - HTTP 401 Unauthorized
            - No link generated
        """

        # Arrange
        file_obj = create_file(original_name="test.txt")

        # Act
        response = api_client.post(
            f"/api/storage/files/{file_obj.id}/public-link/generate/",
            data={},
            format="json",
        )

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        file_obj.refresh_from_db()
        assert file_obj.public_link is None

    def test_generate_link_already_exists_returns_400(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that generating link when one already exists returns error.

        Expected:
            - HTTP 400 Bad Request
            - Error message indicates link exists
            - Existing link is preserved
        """

        # Arrange
        file_obj = create_file(
            owner=authenticated_client.user,
            original_name="test.txt",
            public_link="existing123",
        )

        # Act
        response = authenticated_client.post(
            f"/api/storage/files/{file_obj.id}/public-link/generate/",
            data={},
            format="json",
        )

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "существует" in str(response.data).lower() or "exists" in str(response.data).lower()

        file_obj.refresh_from_db()
        assert file_obj.public_link == "existing123"


# ==============================================================================
# TESTS: PUBLIC LINK DELETION
# ==============================================================================


class TestPublicLinkDeleteView:
    """
    Test suite for public link deletion endpoint.

    Endpoint: DELETE /api/storage/files/{id}/public-link/
    Authentication: Required (owner or admin)
    """

    def test_delete_link_owner_returns_200(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that file owner can delete public link.

        Expected:
            - HTTP 200 OK
            - public_link is set to None
            - has_public_link is False
        """

        # Arrange
        file_obj = create_file(
            owner=authenticated_client.user,
            original_name="test.txt",
            public_link="testlink123",
        )

        # Act
        response = authenticated_client.delete(f"/api/storage/files/{file_obj.id}/public-link/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["has_public_link"] is False
        assert response.data["public_link_url"] is None

        file_obj.refresh_from_db()
        assert file_obj.public_link is None

    def test_delete_link_not_exists_returns_400(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that deleting non-existent link returns error.

        Expected:
            - HTTP 400 Bad Request
            - Error message indicates link is missing
        """

        # Arrange
        file_obj = create_file(
            owner=authenticated_client.user,
            original_name="test.txt",
        )
        assert file_obj.public_link is None

        # Act
        response = authenticated_client.delete(f"/api/storage/files/{file_obj.id}/public-link/")

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert (
            "отсутствует" in str(response.data).lower() or "missing" in str(response.data).lower()
        )

    def test_delete_link_unauthorized_returns_403(
        self, authenticated_client, create_file, another_user_account, temp_media_root
    ):
        """
        Verify that user cannot delete another user's public link.

        Expected:
            - HTTP 403 Forbidden
            - Link remains unchanged
        """

        # Arrange
        file_obj = create_file(
            owner=another_user_account,
            original_name="other_file.txt",
            public_link="otherlink123",
        )

        # Act
        response = authenticated_client.delete(f"/api/storage/files/{file_obj.id}/public-link/")

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN
        file_obj.refresh_from_db()
        assert file_obj.public_link == "otherlink123"


# ==============================================================================
# TESTS: PUBLIC FILE INFO
# ==============================================================================


class TestPublicFileView:
    """
    Test suite for public file info endpoint.

    Endpoint: GET /api/storage/public/{public_link}/
    Authentication: Not required (public access)
    """

    def test_public_info_valid_link_returns_200(self, api_client, create_file, temp_media_root):
        """
        Verify that valid public link returns file information.

        Expected:
            - HTTP 200 OK
            - Safe metadata returned (original_name, size, etc.)
            - No sensitive information (owner, internal paths)
        """

        # Arrange
        create_file(
            original_name="public_document.pdf",
            size=2048,
            comment="Public comment",
            public_link="publink123",
        )

        # Act
        response = api_client.get("/api/storage/public/publink123/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["original_name"] == "public_document.pdf"
        assert response.data["size"] == 2048
        assert response.data["comment"] == "Public comment"
        assert "download_url" in response.data

        # Verify no sensitive information
        assert "owner" not in response.data
        assert "file" not in response.data  # No internal path

    def test_public_info_invalid_link_returns_404(self, db, api_client):
        """
        Verify that invalid public link returns 404.

        Expected:
            - HTTP 404 Not Found
            - Error message indicates invalid link
        """

        # Act
        response = api_client.get("/api/storage/public/invalidlink999/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert (
            "недействительна" in str(response.data).lower()
            or "invalid" in str(response.data).lower()
        )

    def test_public_info_deleted_file_returns_404(self, db, api_client, user_account):
        """
        Verify that accessing deleted file via public link returns 404.

        Expected:
            - HTTP 404 Not Found
        """

        # Arrange
        file_obj = File.objects.create(
            owner=user_account,
            original_name="deleted.txt",
            size=100,
            public_link="deletedlink",
        )

        # Delete the file
        file_obj.delete()

        # Act
        response = api_client.get("/api/storage/public/deletedlink/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_public_info_returns_size_formatted(self, api_client, create_file, temp_media_root):
        """
        Verify that public info includes human-readable size.

        Expected:
            - size_formatted field is present
            - Format is human-readable (Б, КБ, МБ)
        """

        # Arrange
        create_file(
            original_name="test.txt",
            size=5120,  # 5 KB
            public_link="publink456",
        )

        # Act
        response = api_client.get("/api/storage/public/publink456/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert "size_formatted" in response.data
        assert "КБ" in response.data["size_formatted"]


# ==============================================================================
# TESTS: PUBLIC FILE DOWNLOAD
# ==============================================================================


class TestPublicFileDownloadView:
    """
    Test suite for public file download endpoint.

    Endpoint: GET /api/storage/public/{public_link}/download/
    Authentication: Not required (public access)
    """

    def test_public_download_valid_link_returns_200(self, api_client, create_file, temp_media_root):
        """
        Verify that valid public link allows file download.

        Expected:
            - HTTP 200 OK
            - File content returned
            - Content-Type is application/octet-stream
            - Content-Disposition contains original_name
        """

        # Arrange
        create_file(
            original_name="download_me.pdf",
            size=1024,
            public_link="downloadlink123",
        )

        # Act
        response = api_client.get("/api/storage/public/downloadlink123/download/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response["Content-Type"] == "application/octet-stream"
        assert "download_me.pdf" in response["Content-Disposition"]

    def test_public_download_preserves_original_name(
        self, api_client, create_file, temp_media_root
    ):
        """
        Verify that downloaded file has original name (not unique path name).

        Expected:
            - Content-Disposition header contains original_name
            - Not the unique stored filename
        """

        # Arrange
        file_obj = create_file(
            original_name="My Important Document.docx",
            size=2048,
            public_link="doclink789",
        )

        # Act
        response = api_client.get("/api/storage/public/doclink789/download/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert "My Important Document.docx" in response["Content-Disposition"]
        # Verify unique path name is NOT in header
        assert file_obj.file.name.split("/")[-1] not in response["Content-Disposition"]

    def test_public_download_updates_last_downloaded(
        self, api_client, create_file, temp_media_root
    ):
        """
        Verify that public download updates last_downloaded timestamp.

        Expected:
            - last_downloaded is set to current time
            - Multiple downloads update timestamp each time
        """

        # Arrange
        file_obj = create_file(
            original_name="test.txt",
            public_link="tracklink123",
        )
        assert file_obj.last_downloaded is None

        # Act - First download
        api_client.get("/api/storage/public/tracklink123/download/")
        file_obj.refresh_from_db()
        first_download = file_obj.last_downloaded

        # Act - Second download
        import time

        time.sleep(0.1)
        api_client.get("/api/storage/public/tracklink123/download/")
        file_obj.refresh_from_db()
        second_download = file_obj.last_downloaded

        # Assert
        assert first_download is not None
        assert second_download is not None
        assert second_download > first_download

    def test_public_download_invalid_link_returns_404(self, db, api_client):
        """
        Verify that invalid public link returns 404 on download.

        Expected:
            - HTTP 404 Not Found
        """
        # Act
        response = api_client.get("/api/storage/public/invalidlink/download/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_public_download_file_missing_on_disk_returns_404(
        self, api_client, user_account, temp_media_root
    ):
        """
        Verify that download returns 404 if physical file is missing.

        Scenario:
            1. Create file in database
            2. Manually remove physical file from disk
            3. Attempt download via public link

        Expected:
            - HTTP 404 Not Found
            - Error message indicates file not found on server
        """

        # Arrange
        File.objects.create(
            owner=user_account,
            original_name="missing.txt",
            size=100,
            public_link="missinglink",
        )

        # Act
        response = api_client.get("/api/storage/public/missinglink/download/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert (
            "не найден" in str(response.data).lower() or "not found" in str(response.data).lower()
        )


# ==============================================================================
# TESTS: PUBLIC LINK SECURITY
# ==============================================================================


class TestPublicLinkSecurity:
    """
    Test suite for public link security and anonymization.
    """

    def test_public_link_does_not_contain_user_id(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that public link does not contain user ID.

        Expected:
            - public_link URL does not contain user ID
            - Link is anonymized
        """

        # Arrange
        file_obj = create_file(
            owner=authenticated_client.user,
            original_name="test.txt",
        )

        # Act
        response = authenticated_client.post(
            f"/api/storage/files/{file_obj.id}/public-link/generate/",
            data={},
            format="json",
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        public_url = response.data["public_link_url"]
        assert str(authenticated_client.user.id) not in public_url

    def test_public_link_does_not_contain_original_name(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that public link does not contain original filename.

        Expected:
            - public_link URL does not contain original_name
            - Link reveals no information about file content
        """

        # Arrange
        file_obj = create_file(
            owner=authenticated_client.user,
            original_name="confidential_salary_report_2024.xlsx",
        )

        # Act
        response = authenticated_client.post(
            f"/api/storage/files/{file_obj.id}/public-link/generate/",
            data={},
            format="json",
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        public_url = response.data["public_link_url"]
        assert "confidential" not in public_url.lower()
        assert "salary" not in public_url.lower()
        assert "2024" not in public_url

    def test_public_link_does_not_contain_storage_path(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that public link does not contain storage path structure.

        Expected:
            - public_link URL does not contain /storage/{user_id}/
            - Internal path structure is hidden
        """

        # Arrange
        file_obj = create_file(
            owner=authenticated_client.user,
            original_name="test.txt",
        )

        # Act
        response = authenticated_client.post(
            f"/api/storage/files/{file_obj.id}/public-link/generate/",
            data={},
            format="json",
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK

        public_url = response.data["public_link_url"]
        assert f"/storage/{file_obj.owner.id}/" not in public_url
        assert f"storage/{file_obj.owner.id}" not in public_url

    def test_public_link_is_unique_across_all_files(
        self, admin_client, create_file, user_account, another_user_account, temp_media_root
    ):
        """
        Verify that public links are unique across all users.

        Expected:
            - Each file gets unique public link
            - No collisions between different users' files
        """

        # Arrange
        files = [
            create_file(
                owner=user_account,
                original_name=f"file_{i}.txt",
            )
            for i in range(5)
        ]
        links = [
            admin_client.post(
                f"/api/storage/files/{file_obj.id}/public-link/generate/",
                data={},
                format="json",
            ).data["public_link_url"]
            for file_obj in files
        ]

        # Assert
        assert len(set(links)) == 5  # All unique

    def test_public_access_does_not_require_authentication(
        self, api_client, create_file, temp_media_root
    ):
        """
        Verify that public file access works without authentication.

        Expected:
            - Unauthenticated client can access public file info
            - Unauthenticated client can download public file
        """

        # Arrange
        create_file(
            original_name="public.txt",
            public_link="publicaccess123",
        )

        # Act - Info
        response_info = api_client.get("/api/storage/public/publicaccess123/")

        # Act - Download
        response_download = api_client.get("/api/storage/public/publicaccess123/download/")

        # Assert
        assert response_info.status_code == status.HTTP_200_OK
        assert response_download.status_code == status.HTTP_200_OK
