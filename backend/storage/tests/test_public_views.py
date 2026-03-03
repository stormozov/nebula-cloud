"""
Pytest tests for public file access views.

This module contains comprehensive tests for public file access via public_link:
- PublicFileView: Preview file metadata without authentication
- PublicFileDownloadView: Download file without authentication
"""

# pylint: disable=unused-argument
# pylint: disable=missing-function-docstring

import re
import pytest
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient

from storage.models import File

User = get_user_model()

pytestmark = pytest.mark.django_db

# ==================================================================================================
# TEST CLASS: PUBLIC FILE VIEW (PREVIEW)
# ==================================================================================================


class TestPublicFileView:
    """Tests for GET /api/storage/public/{public_link}/ endpoint."""

    def test_public_preview_returns_200_with_file_metadata(
        self, api_client: APIClient, file_with_public_link: File
    ) -> None:
        """
        Test: Public preview returns 200 with file metadata.

        Scenario: Anonymous user requests file info via valid public link.
        Expected: HTTP 200 with safe metadata (no owner info).
        """

        # Arrange
        public_link = file_with_public_link.public_link

        # Act
        response = api_client.get(f"/api/storage/public/{public_link}/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["original_name"] == file_with_public_link.original_name
        assert response.data["size"] == file_with_public_link.size

    def test_public_preview_excludes_owner_info(
        self, api_client: APIClient, file_with_public_link: File
    ) -> None:
        """
        Test: Public preview does not expose owner information.

        Scenario: Anonymous user requests file info via public link.
        Expected: Response contains no owner email or internal paths.
        """

        # Arrange
        public_link = file_with_public_link.public_link
        sensitive_fields = {"owner", "email", "user"}

        # Act
        response = api_client.get(f"/api/storage/public/{public_link}/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert not sensitive_fields & response.data.keys()

    def test_public_preview_includes_download_url(
        self, api_client: APIClient, file_with_public_link: File
    ) -> None:
        """
        Test: Public preview includes public download URL.

        Scenario: Anonymous user requests file info via public link.
        Expected: Response contains download_url for public access.
        """

        # Arrange
        public_link = file_with_public_link.public_link

        # Act
        response = api_client.get(f"/api/storage/public/{public_link}/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert "download_url" in response.data
        assert str(public_link) in response.data["download_url"]

    def test_public_preview_invalid_link_returns_404(self, api_client: APIClient) -> None:
        """
        Test: Public preview returns 404 for invalid public link.

        Scenario: Anonymous user requests file info with non-existent link.
        Expected: HTTP 404 Not Found.
        """

        # Arrange
        invalid_link = "00000000-0000-0000-0000-000000000000"

        # Act
        response = api_client.get(f"/api/storage/public/{invalid_link}/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "detail" in response.data

    def test_public_preview_empty_link_returns_404(self, api_client: APIClient) -> None:
        """
        Test: Public preview returns 404 for empty public link.

        Scenario: Anonymous user requests file info with empty link.
        Expected: HTTP 404 Not Found.
        """

        # Arrange
        empty_link = ""

        # Act
        response = api_client.get(f"/api/storage/public/{empty_link}/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_public_preview_deleted_file_returns_404(
        self, api_client: APIClient, create_file, user_account
    ) -> None:
        """
        Test: Public preview returns 404 after file is deleted.

        Scenario: File with public link is deleted, link accessed.
        Expected: HTTP 404 Not Found.
        """

        # Arrange
        file_obj = create_file(
            owner=user_account,
            original_name="to_delete.txt",
            size=100,
        )
        file_obj.generate_public_link(force=True)
        file_obj.save(update_fields=["public_link"])
        public_link = file_obj.public_link

        # Delete the file
        file_obj.delete()

        # Act
        response = api_client.get(f"/api/storage/public/{public_link}/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_public_preview_works_without_authentication(
        self, api_client: APIClient, file_with_public_link: File
    ) -> None:
        """
        Test: Public preview works without any authentication.

        Scenario: Unauthenticated client accesses public link.
        Expected: HTTP 200 (AllowAny permission).
        """

        # Arrange
        public_link = file_with_public_link.public_link

        # Act
        api_client.credentials()
        response = api_client.get(f"/api/storage/public/{public_link}/")

        # Assert
        assert response.status_code == status.HTTP_200_OK

    def test_public_preview_authenticated_user_same_result(
        self, authenticated_client: APIClient, file_with_public_link: File
    ) -> None:
        """
        Test: Public preview returns same data for authenticated user.

        Scenario: Authenticated user accesses public link (different from owner).
        Expected: HTTP 200 with same public metadata.
        """

        # Arrange
        public_link = file_with_public_link.public_link

        # Act
        response = authenticated_client.get(f"/api/storage/public/{public_link}/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["original_name"] == file_with_public_link.original_name


# ==================================================================================================
# TEST CLASS: PUBLIC FILE DOWNLOAD VIEW
# ==================================================================================================


class TestPublicFileDownloadView:
    """Tests for GET /api/storage/public/{public_link}/download/ endpoint."""

    def test_public_download_returns_file_response(
        self, api_client: APIClient, file_with_public_link: File
    ) -> None:
        """
        Test: Public download returns FileResponse with correct headers.

        Scenario: Anonymous user downloads file via public link.
        Expected: HTTP 200 with FileResponse, Content-Disposition header.
        """

        # Arrange
        public_link = file_with_public_link.public_link

        # Act
        response = api_client.get(f"/api/storage/public/{public_link}/download/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response["Content-Disposition"].startswith("attachment")
        assert file_with_public_link.original_name in response["Content-Disposition"]

    def test_public_download_includes_content_length(
        self, api_client: APIClient, file_with_public_link: File
    ) -> None:
        """
        Test: Public download includes Content-Length header.

        Scenario: Anonymous user downloads file via public link.
        Expected: Content-Length header matches file size.
        """

        # Arrange
        public_link = file_with_public_link.public_link

        # Act
        response = api_client.get(f"/api/storage/public/{public_link}/download/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response["Content-Length"] == str(file_with_public_link.size)

    def test_public_download_updates_last_downloaded(
        self, api_client: APIClient, file_with_public_link: File
    ) -> None:
        """
        Test: Public download updates file's last_downloaded timestamp.

        Scenario: File downloaded via public link.
        Expected: last_downloaded field is updated.
        """

        # Arrange
        public_link = file_with_public_link.public_link
        file_with_public_link.last_downloaded = None
        file_with_public_link.save(update_fields=["last_downloaded"])

        # Act
        api_client.get(f"/api/storage/public/{public_link}/download/")
        file_with_public_link.refresh_from_db()

        # Assert
        assert file_with_public_link.last_downloaded is not None

    def test_public_download_invalid_link_returns_404(self, api_client: APIClient) -> None:
        """
        Test: Public download returns 404 for invalid public link.

        Scenario: Anonymous user attempts download with non-existent link.
        Expected: HTTP 404 Not Found.
        """

        # Arrange
        invalid_link = "00000000-0000-0000-0000-000000000000"

        # Act
        response = api_client.get(f"/api/storage/public/{invalid_link}/download/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_public_download_empty_link_returns_404(self, api_client: APIClient) -> None:
        """
        Test: Public download returns 404 for empty public link.

        Scenario: Anonymous user attempts download with empty link.
        Expected: HTTP 404 Not Found.
        """

        # Arrange
        empty_link = ""

        # Act
        response = api_client.get(f"/api/storage/public/{empty_link}/download/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_public_download_works_without_authentication(
        self, api_client: APIClient, file_with_public_link: File
    ) -> None:
        """
        Test: Public download works without any authentication.

        Scenario: Unauthenticated client downloads via public link.
        Expected: HTTP 200 (AllowAny permission).
        """

        # Arrange
        public_link = file_with_public_link.public_link
        api_client.credentials()

        # Act
        response = api_client.get(f"/api/storage/public/{public_link}/download/")

        # Assert
        assert response.status_code == status.HTTP_200_OK

    def test_public_download_file_owner_can_use_link(
        self, authenticated_client: APIClient, file_with_public_link: File
    ) -> None:
        """
        Test: File owner can download via their own public link.

        Scenario: Owner accesses their file via public link.
        Expected: HTTP 200 (public links work for anyone).
        """

        # Arrange
        public_link = file_with_public_link.public_link

        # Act
        response = authenticated_client.get(f"/api/storage/public/{public_link}/download/")

        # Assert
        assert response.status_code == status.HTTP_200_OK

    def test_public_download_admin_can_use_any_link(
        self, admin_client: APIClient, file_with_public_link: File
    ) -> None:
        """
        Test: Admin can download any file via public link.

        Scenario: Admin accesses file via public link.
        Expected: HTTP 200 (public links work for anyone).
        """

        # Arrange
        public_link = file_with_public_link.public_link

        # Act
        response = admin_client.get(f"/api/storage/public/{public_link}/download/")

        # Assert
        assert response.status_code == status.HTTP_200_OK


# ==================================================================================================
# TEST CLASS: PUBLIC LINK GENERATION (VIA FILEVIEWSET @ACTION)
# ==================================================================================================


class TestPublicLinkGeneration:
    """Tests for POST /api/storage/files/{id}/public-link/generate/ endpoint."""

    def test_generate_public_link_returns_200_with_link(
        self, authenticated_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Generate public link returns 200 with new link.

        Scenario: User generates public link for their file.
        Expected: HTTP 200 with public_link and public_link_url.
        """

        # Arrange
        file_id = uploaded_file.id

        # Act
        response = authenticated_client.post(f"/api/storage/files/{file_id}/public-link/generate/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["has_public_link"] is True
        assert response.data["public_link_url"] is not None

    def test_generate_public_link_creates_uuid_link(
        self, authenticated_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Generated public link is UUID format.

        Scenario: User generates public link for their file.
        Expected: public_link is valid UUID string.
        """

        # Arrange
        file_id = uploaded_file.id
        uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        nanoid_pattern = r"^[A-Za-z0-9_-]{21}$"

        # Act
        response = authenticated_client.post(f"/api/storage/files/{file_id}/public-link/generate/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["has_public_link"] is True
        assert response.data["public_link_url"] is not None

        # Assert: Check if public link exists
        uploaded_file.refresh_from_db()
        assert uploaded_file.public_link is not None

        # Assert: Check if public link is UUID
        link_str = str(uploaded_file.public_link)
        assert re.match(uuid_pattern, link_str) or re.match(nanoid_pattern, link_str)

    def test_generate_public_link_replaces_existing(
        self, authenticated_client: APIClient, file_with_public_link: File
    ) -> None:
        """
        Test: Generate replaces existing public link.

        Scenario: User generates new link when one already exists.
        Expected: HTTP 200 with new different link.
        """

        # Arrange
        file_id = file_with_public_link.id
        old_link = file_with_public_link.public_link

        # Act
        response = authenticated_client.post(f"/api/storage/files/{file_id}/public-link/generate/")
        public_link = response.data["public_link_url"]

        # Assert
        assert response.status_code == status.HTTP_200_OK
        # Assert: Link should be regenerated (force=True)
        assert public_link is not None
        assert public_link != old_link

    def test_generate_public_link_other_user_file_returns_403(
        self, authenticated_client: APIClient, another_user_file: File
    ) -> None:
        """
        Test: Generate returns 403 for another user's file.

        Scenario: User attempts to generate link for file owned by different user.
        Expected: HTTP 403 Forbidden.
        """

        # Arrange
        file_id = another_user_file.id

        # Act
        response = authenticated_client.post(f"/api/storage/files/{file_id}/public-link/generate/")

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_generate_public_link_unauthenticated_returns_401(
        self, api_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Generate returns 401 for unauthenticated request.

        Scenario: Guest user attempts to generate public link.
        Expected: HTTP 401 Unauthorized.
        """

        # Arrange
        file_id = uploaded_file.id
        api_client.credentials()

        # Act
        response = api_client.post(f"/api/storage/files/{file_id}/public-link/generate/")

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_generate_public_link_nonexistent_file_returns_404(
        self, authenticated_client: APIClient
    ) -> None:
        """
        Test: Generate returns 404 for non-existent file.

        Scenario: User attempts to generate link for invalid file ID.
        Expected: HTTP 404 Not Found.
        """

        # Arrange
        nonexistent_id = 99999

        # Act
        response = authenticated_client.post(
            f"/api/storage/files/{nonexistent_id}/public-link/generate/"
        )

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_generate_public_link_admin_can_generate_for_any_user(
        self, admin_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Admin can generate public link for any user's file.

        Scenario: Admin generates link for regular user's file.
        Expected: HTTP 200 with public link.
        """

        # Arrange
        file_id = uploaded_file.id

        # Act
        response = admin_client.post(f"/api/storage/files/{file_id}/public-link/generate/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["has_public_link"] is True


# ==================================================================================================
# TEST CLASS: PUBLIC LINK DELETION (VIA FILEVIEWSET @ACTION)
# ==================================================================================================


class TestPublicLinkDeletion:
    """Tests for DELETE /api/storage/files/{id}/public-link/ endpoint."""

    def test_delete_public_link_returns_200_without_link(
        self, authenticated_client: APIClient, file_with_public_link: File
    ) -> None:
        """
        Test: Delete public link returns 200 without link.

        Scenario: User deletes public link for their file.
        Expected: HTTP 200 with has_public_link=False.
        """

        # Arrange
        file_id = file_with_public_link.id

        # Act
        response = authenticated_client.delete(f"/api/storage/files/{file_id}/public-link/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["has_public_link"] is False
        assert response.data["public_link_url"] is None

    def test_delete_public_link_removes_from_database(
        self, authenticated_client: APIClient, file_with_public_link: File
    ) -> None:
        """
        Test: Delete public link removes it from database.

        Scenario: User deletes public link for their file.
        Expected: File.public_link is NULL in database.
        """

        # Arrange
        file_id = file_with_public_link.id

        # Act
        authenticated_client.delete(f"/api/storage/files/{file_id}/public-link/")
        file_with_public_link.refresh_from_db()

        # Assert
        assert file_with_public_link.public_link is None

    def test_delete_public_link_no_existing_link_returns_400(
        self, authenticated_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Delete returns 400 when no public link exists.

        Scenario: User attempts to delete non-existent public link.
        Expected: HTTP 400 Bad Request with error message.
        """

        # Arrange
        file_id = uploaded_file.id

        # Act
        response = authenticated_client.delete(f"/api/storage/files/{file_id}/public-link/")

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "detail" in response.data

    def test_delete_public_link_other_user_file_returns_403(
        self, authenticated_client: APIClient, another_user_account, create_file: File
    ) -> None:
        """
        Test: Delete returns 403 for another user's file.

        Scenario: User attempts to delete link for file owned by different user.
        Expected: HTTP 403 Forbidden.
        """

        # Arrange
        another_user_file_with_link = create_file(
            owner=another_user_account,
            original_name="others_public.txt",
            size=100,
        )
        another_user_file_with_link.generate_public_link(force=True)
        another_user_file_with_link.save(update_fields=["public_link"])
        file_id = another_user_file_with_link.id

        # Act
        response = authenticated_client.delete(f"/api/storage/files/{file_id}/public-link/")

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_delete_public_link_unauthenticated_returns_401(
        self, api_client: APIClient, file_with_public_link: File
    ) -> None:
        """
        Test: Delete returns 401 for unauthenticated request.

        Scenario: Guest user attempts to delete public link.
        Expected: HTTP 401 Unauthorized.
        """

        # Arrange
        file_id = file_with_public_link.id
        api_client.credentials()

        # Act
        response = api_client.delete(f"/api/storage/files/{file_id}/public-link/")

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_delete_public_link_nonexistent_file_returns_404(
        self, authenticated_client: APIClient
    ) -> None:
        """
        Test: Delete returns 404 for non-existent file.

        Scenario: User attempts to delete link for invalid file ID.
        Expected: HTTP 404 Not Found.
        """

        # Arrange
        nonexistent_id = 99999

        # Act
        response = authenticated_client.delete(f"/api/storage/files/{nonexistent_id}/public-link/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_delete_public_link_admin_can_delete_any_user_link(
        self, admin_client: APIClient, file_with_public_link: File
    ) -> None:
        """
        Test: Admin can delete any user's public link.

        Scenario: Admin deletes public link for regular user's file.
        Expected: HTTP 200 with link removed.
        """

        # Arrange
        file_id = file_with_public_link.id

        # Act
        response = admin_client.delete(f"/api/storage/files/{file_id}/public-link/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["has_public_link"] is False


# ==================================================================================================
# TEST CLASS: PUBLIC LINK INTEGRATION
# ==================================================================================================


class TestPublicLinkIntegration:
    """Integration tests for complete public link workflow."""

    def test_full_public_link_workflow(
        self, authenticated_client: APIClient, api_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Complete public link workflow from generation to download.

        Scenario: User generates link, anonymous user accesses via link.
        Expected: Full workflow succeeds end-to-end.
        """

        # Arrange: Generate public link
        file_id = uploaded_file.id

        # Act 1: Generate link
        generate_response = authenticated_client.post(
            f"/api/storage/files/{file_id}/public-link/generate/"
        )

        # Assert 1: Link generated
        assert generate_response.status_code == status.HTTP_200_OK
        public_url = generate_response.data["public_link_url"]

        # Act 2: Anonymous user previews file
        preview_response = api_client.get(public_url)

        # Assert 2: Preview works
        assert preview_response.status_code == status.HTTP_200_OK
        assert preview_response.data["original_name"] == uploaded_file.original_name

        # Act 3: Anonymous user downloads file
        download_url = preview_response.data["download_url"]
        download_response = api_client.get(download_url)

        # Assert 3: Download works
        assert download_response.status_code == status.HTTP_200_OK
        assert download_response["Content-Disposition"].startswith("attachment")

    def test_public_link_access_does_not_require_owner_permission(self, api_client, create_file):
        """
        Verify that public link access bypasses owner permission checks.

        Scenario:
            - User generates public link
            - User tries to access file via public link

        Expected:
            - Unauthenticated user can access file via public link
            - No 401/403 error for public endpoints
        """

        # Arrange
        create_file(
            original_name="public_file.txt",
            public_link="public123",
        )

        # Act
        # Act - Public info access
        response_info = api_client.get("/api/storage/public/public123/")

        # Act - Public download access
        response_download = api_client.get("/api/storage/public/public123/download/")

        # Assert
        assert response_info.status_code == status.HTTP_200_OK
        assert response_download.status_code == status.HTTP_200_OK

    def test_public_link_becomes_invalid_after_deletion(
        self, authenticated_client: APIClient, api_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Public link becomes invalid after deletion.

        Scenario: User generates link, deletes it, anonymous tries to access.
        Expected: Access fails after deletion.
        """

        # Arrange
        file_id = uploaded_file.id

        generate_response = authenticated_client.post(
            f"/api/storage/files/{file_id}/public-link/generate/"
        )
        public_url = generate_response.data["public_link_url"]

        authenticated_client.delete(f"/api/storage/files/{file_id}/public-link/")

        # Act: Anonymous tries to access deleted link
        response = api_client.get(public_url)

        # Assert: Access denied
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.parametrize("file_index", range(5))
    def test_each_public_link_returns_correct_file(
        self,
        authenticated_client: APIClient,
        api_client: APIClient,
        multiple_files: list[File],
        file_index: int,
    ) -> None:
        """
        Test: Each public link returns correct file data.

        Scenario: User accesses each of 5 files via public link.
        Expected: Each link returns matching file metadata.
        """

        # Arrange
        file_obj = multiple_files[file_index]

        # Generate link
        response = authenticated_client.post(
            f"/api/storage/files/{file_obj.id}/public-link/generate/"
        )
        assert response.status_code == status.HTTP_200_OK

        # Act
        link_response = api_client.get(response.data["public_link_url"])

        # Assert
        assert link_response.status_code == status.HTTP_200_OK
        assert link_response.data["original_name"] == file_obj.original_name
        assert link_response.data["size"] == file_obj.size
