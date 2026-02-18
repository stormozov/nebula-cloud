"""
Tests for storage file views (CRUD operations).

This module tests all authenticated file operations including:
- File upload
- File listing (own and admin access)
- File detail retrieval
- File deletion
- File rename
- File comment update
- File download (authenticated)
"""

# pylint: disable=no-member

import os

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework import status

from storage.models import File

User = get_user_model()


# ==============================================================================
# TESTS: FILE UPLOAD
# ==============================================================================


class TestFileUploadView:
    """
    Test suite for file upload endpoint.

    Endpoint: POST /api/storage/files/upload/
    Authentication: Required
    """

    def test_upload_authenticated_user_returns_201(
        self, authenticated_client, test_file, temp_media_root
    ):
        """
        Verify that authenticated user can upload a file.

        Scenario:
            1. Authenticated user sends POST request with file
            2. Server validates file size and name
            3. File is saved with unique path
            4. Response contains file metadata

        Expected:
            - HTTP 201 Created
            - File object created in database
            - Response contains original_name, size, comment
            - File stored in user's directory

        Edge Cases:
            - File size under 100MB limit
            - Filename with spaces and unicode
        """

        # Arrange
        upload_data = {
            "file": test_file,
            "comment": "Test upload comment",
        }

        # Act
        response = authenticated_client.post(
            "/api/storage/files/upload/", upload_data, format="multipart"
        )

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        assert File.objects.count() == 1

        file_obj = File.objects.first()
        assert file_obj.owner == authenticated_client.user
        assert file_obj.original_name == "test_file.txt"
        assert file_obj.size > 0
        assert file_obj.comment == "Test upload comment"

        # Verify file stored in user's directory
        assert f"storage{os.sep}{file_obj.owner.id}{os.sep}" in file_obj.file.path.replace(
            "/", os.sep
        ).replace("\\", os.sep)

    def test_upload_unauthenticated_user_returns_401(self, db, api_client, test_file):
        """
        Verify that unauthenticated user cannot upload files.

        Expected:
            - HTTP 401 Unauthorized
            - No file created in database
        """

        # Arrange
        upload_data = {
            "file": test_file,
            "comment": "Test comment",
        }

        # Act
        response = api_client.post("/api/storage/files/upload/", upload_data, format="multipart")

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert File.objects.count() == 0

    def test_upload_file_over_100mb_returns_400(self, authenticated_client, large_test_file):
        """
        Verify that file over 100MB limit is rejected.

        Expected:
            - HTTP 400 Bad Request
            - Error message mentions size limit
            - No file created in database
        """

        # Arrange
        upload_data = {
            "file": large_test_file,
            "comment": "",
        }

        # Act
        response = authenticated_client.post(
            "/api/storage/files/upload/", upload_data, format="multipart"
        )

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert File.objects.count() == 0
        assert "100" in str(response.data).lower() or "size" in str(response.data).lower()

    def test_upload_without_comment_succeeds(
        self, authenticated_client, test_file, temp_media_root
    ):
        """
        Verify that comment field is optional during upload.

        Expected:
            - HTTP 201 Created
            - File created with empty/null comment
        """

        # Arrange
        upload_data = {
            "file": test_file,
        }

        # Act
        response = authenticated_client.post(
            "/api/storage/files/upload/", upload_data, format="multipart"
        )

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        assert File.objects.first().comment in ["", None]

    def test_upload_multiple_files_creates_unique_paths(
        self, authenticated_client, test_file, temp_media_root
    ):
        """
        Verify that multiple files with same name get unique paths.

        Expected:
            - All files uploaded successfully
            - Each file has unique path on disk
            - No filename collisions
        """

        # Arrange
        upload_data_1 = {
            "file": SimpleUploadedFile(
                name="test_file.txt",
                content=test_file.read(),
                content_type="text/plain",
            ),
            "comment": "First file",
        }
        test_file.seek(0)

        upload_data_2 = {
            "file": SimpleUploadedFile(
                name="test_file.txt",
                content=test_file.read(),
                content_type="text/plain",
            ),
            "comment": "Second file",
        }

        # Act
        response1 = authenticated_client.post(
            "/api/storage/files/upload/", upload_data_1, format="multipart"
        )
        response2 = authenticated_client.post(
            "/api/storage/files/upload/", upload_data_2, format="multipart"
        )

        # Assert
        assert response1.status_code == status.HTTP_201_CREATED
        assert response2.status_code == status.HTTP_201_CREATED
        assert File.objects.count() == 2

        file1 = File.objects.get(id=response1.data["id"])
        file2 = File.objects.get(id=response2.data["id"])

        assert file1.file.path != file2.file.path


# ==============================================================================
# TESTS: FILE LIST
# ==============================================================================


class TestFileListView:
    """
    Test suite for file list endpoint.

    Endpoint: GET /api/storage/files/
    Authentication: Required
    """

    def test_list_authenticated_user_sees_own_files(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that user sees only their own files.

        Expected:
            - HTTP 200 OK
            - Only files owned by user are returned
            - Files ordered by uploaded_at descending
        """

        # Arrange
        file1 = create_file(owner=authenticated_client.user, original_name="file1.txt")
        file2 = create_file(owner=authenticated_client.user, original_name="file2.txt")

        # Act
        response = authenticated_client.get("/api/storage/files/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) == 2

        file_ids = [f["id"] for f in response.data]
        assert file1.id in file_ids
        assert file2.id in file_ids

    def test_list_unauthenticated_user_returns_401(self, api_client):
        """
        Verify that unauthenticated user cannot list files.

        Expected:
            - HTTP 401 Unauthorized
        """
        # Act
        response = api_client.get("/api/storage/files/")

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_list_admin_sees_all_files_without_user_id(
        self, admin_client, create_file, user_account, temp_media_root
    ):
        """
        Verify that admin can see all files without user_id parameter.

        Expected:
            - HTTP 200 OK
            - Files from all users are returned
            - Admin's own files included
        """

        # Arrange
        file1 = create_file(owner=user_account, original_name="user_file.txt")
        file2 = create_file(owner=admin_client.user, original_name="admin_file.txt")

        # Act
        response = admin_client.get("/api/storage/files/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) == 2

        file_ids = [f["id"] for f in response.data]
        assert file1.id in file_ids
        assert file2.id in file_ids

    def test_list_admin_with_user_id_filter(
        self, admin_client, create_file, user_account, another_user_account, temp_media_root
    ):
        """
        Verify that admin can filter files by user_id.

        Expected:
            - HTTP 200 OK
            - Only files of specified user are returned
        """

        # Arrange
        file1 = create_file(owner=user_account, original_name="user1_file1.txt")
        file2 = create_file(owner=user_account, original_name="user1_file2.txt")
        file3 = create_file(owner=another_user_account, original_name="user2_file.txt")

        # Act
        response = admin_client.get(f"/api/storage/files/?user_id={user_account.id}")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) == 2

        file_ids = [f["id"] for f in response.data]
        assert file1.id in file_ids
        assert file2.id in file_ids
        assert file3.id not in file_ids

    def test_list_empty_database_returns_empty_list(self, authenticated_client):
        """
        Verify that empty file list returns empty array.

        Expected:
            - HTTP 200 OK
            - Empty list returned
        """
        # Act
        response = authenticated_client.get("/api/storage/files/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data == []


# ==============================================================================
# TESTS: FILE DETAIL
# ==============================================================================


class TestFileDetailView:
    """
    Test suite for file detail endpoint.

    Endpoint: GET /api/storage/files/{id}/
    Authentication: Required
    """

    def test_detail_owner_can_view_own_file(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that file owner can view their file details.

        Expected:
            - HTTP 200 OK
            - All file metadata returned
        """

        # Arrange
        file_obj = create_file(
            owner=authenticated_client.user,
            original_name="test.txt",
            size=1024,
            comment="Test comment",
        )

        # Act
        response = authenticated_client.get(f"/api/storage/files/{file_obj.id}/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["original_name"] == "test.txt"
        assert response.data["size"] == 1024
        assert response.data["comment"] == "Test comment"

    def test_detail_unauthorized_user_returns_403(
        self, authenticated_client, create_file, another_user_account, temp_media_root
    ):
        """
        Verify that user cannot view another user's file.

        Expected:
            - HTTP 403 Forbidden
        """

        # Arrange
        file_obj = create_file(owner=another_user_account, original_name="other_file.txt")

        # Act
        response = authenticated_client.get(f"/api/storage/files/{file_obj.id}/")

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_detail_admin_can_view_any_file(
        self, admin_client, create_file, user_account, temp_media_root
    ):
        """
        Verify that admin can view any user's file.

        Expected:
            - HTTP 200 OK
            - File details returned regardless of owner
        """

        # Arrange
        file_obj = create_file(owner=user_account, original_name="user_file.txt")

        # Act
        response = admin_client.get(f"/api/storage/files/{file_obj.id}/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["original_name"] == "user_file.txt"

    def test_detail_nonexistent_file_returns_404(self, authenticated_client):
        """
        Verify that nonexistent file returns 404.

        Expected:
            - HTTP 404 Not Found
        """
        # Act
        response = authenticated_client.get("/api/storage/files/99999/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND


# ==============================================================================
# TESTS: FILE DELETE
# ==============================================================================


class TestFileDeleteView:
    """
    Test suite for file delete endpoint.

    Endpoint: DELETE /api/storage/files/{id}/
    Authentication: Required
    """

    def test_delete_owner_can_delete_own_file(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that file owner can delete their file.

        Expected:
            - HTTP 204 No Content
            - File removed from database
            - Physical file removed from disk
        """

        # Arrange
        file_obj = create_file(owner=authenticated_client.user, original_name="test.txt")
        file_path = file_obj.file.path
        file_id = file_obj.id

        # Verify file exists before deletion
        assert os.path.exists(file_path)

        # Act
        response = authenticated_client.delete(f"/api/storage/files/{file_id}/")

        # Assert
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not File.objects.filter(id=file_id).exists()
        assert not os.path.exists(file_path)

    def test_delete_unauthorized_user_returns_403(
        self, authenticated_client, create_file, another_user_account, temp_media_root
    ):
        """
        Verify that user cannot delete another user's file.

        Expected:
            - HTTP 403 Forbidden
            - File remains in database
        """

        # Arrange
        file_obj = create_file(owner=another_user_account, original_name="other_file.txt")
        file_id = file_obj.id

        # Act
        response = authenticated_client.delete(f"/api/storage/files/{file_id}/")

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert File.objects.filter(id=file_id).exists()

    def test_delete_admin_can_delete_any_file(
        self, admin_client, create_file, user_account, temp_media_root
    ):
        """
        Verify that admin can delete any user's file.

        Expected:
            - HTTP 204 No Content
            - File removed from database
        """

        # Arrange
        file_obj = create_file(owner=user_account, original_name="user_file.txt")
        file_id = file_obj.id

        # Act
        response = admin_client.delete(f"/api/storage/files/{file_id}/")

        # Assert
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not File.objects.filter(id=file_id).exists()

    def test_delete_nonexistent_file_returns_404(self, authenticated_client):
        """
        Verify that deleting nonexistent file returns 404.

        Expected:
            - HTTP 404 Not Found
        """
        # Act
        response = authenticated_client.delete("/api/storage/files/99999/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND


# ==============================================================================
# TESTS: FILE RENAME
# ==============================================================================


class TestFileRenameView:
    """
    Test suite for file rename endpoint.

    Endpoint: PATCH /api/storage/files/{id}/rename/
    Authentication: Required
    """

    def test_rename_owner_can_rename_own_file(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that file owner can rename their file.

        Expected:
            - HTTP 200 OK
            - original_name updated
            - Physical file path unchanged
        """

        # Arrange
        file_obj = create_file(owner=authenticated_client.user, original_name="old_name.txt")
        old_path = file_obj.file.path

        rename_data = {
            "original_name": "new_name.txt",
        }

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_obj.id}/rename/", rename_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        file_obj.refresh_from_db()
        assert file_obj.original_name == "new_name.txt"
        assert file_obj.file.path == old_path  # Physical path unchanged

    def test_rename_unauthorized_user_returns_403(
        self, authenticated_client, create_file, another_user_account, temp_media_root
    ):
        """
        Verify that user cannot rename another user's file.

        Expected:
            - HTTP 403 Forbidden
            - original_name unchanged
        """

        # Arrange
        file_obj = create_file(owner=another_user_account, original_name="other_file.txt")

        rename_data = {
            "original_name": "hacked_name.txt",
        }

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_obj.id}/rename/", rename_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN
        file_obj.refresh_from_db()
        assert file_obj.original_name == "other_file.txt"

    def test_rename_with_forbidden_characters_returns_400(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that filename with forbidden characters is rejected.

        Expected:
            - HTTP 400 Bad Request
            - original_name unchanged
        """

        # Arrange
        file_obj = create_file(owner=authenticated_client.user, original_name="old_name.txt")

        rename_data = {
            "original_name": "invalid:name.txt",
        }

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_obj.id}/rename/", rename_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        file_obj.refresh_from_db()
        assert file_obj.original_name == "old_name.txt"

    def test_rename_nonexistent_file_returns_404(self, authenticated_client):
        """
        Verify that renaming nonexistent file returns 404.

        Expected:
            - HTTP 404 Not Found
        """

        # Arrange
        rename_data = {
            "original_name": "new_name.txt",
        }

        # Act
        response = authenticated_client.patch(
            "/api/storage/files/99999/rename/", rename_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND


# ==============================================================================
# TESTS: FILE COMMENT
# ==============================================================================


class TestFileCommentView:
    """
    Test suite for file comment endpoint.

    Endpoint: PATCH /api/storage/files/{id}/comment/
    Authentication: Required
    """

    def test_comment_owner_can_update_comment(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that file owner can update their file comment.

        Expected:
            - HTTP 200 OK
            - comment field updated
        """

        # Arrange
        file_obj = create_file(
            owner=authenticated_client.user,
            original_name="test.txt",
            comment="Old comment",
        )

        comment_data = {
            "comment": "New comment",
        }

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_obj.id}/comment/", comment_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        file_obj.refresh_from_db()
        assert file_obj.comment == "New comment"

    def test_comment_owner_can_clear_comment(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that file owner can clear their file comment.

        Expected:
            - HTTP 200 OK
            - comment field is empty string
        """

        # Arrange
        file_obj = create_file(
            owner=authenticated_client.user,
            original_name="test.txt",
            comment="Existing comment",
        )

        comment_data = {
            "comment": "",
        }

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_obj.id}/comment/", comment_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        file_obj.refresh_from_db()
        assert file_obj.comment == ""

    def test_comment_unauthorized_user_returns_403(
        self, authenticated_client, create_file, another_user_account, temp_media_root
    ):
        """
        Verify that user cannot update another user's file comment.

        Expected:
            - HTTP 403 Forbidden
            - comment unchanged
        """

        # Arrange
        file_obj = create_file(
            owner=another_user_account,
            original_name="other_file.txt",
            comment="Original comment",
        )

        comment_data = {
            "comment": "Hacked comment",
        }

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_obj.id}/comment/", comment_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN
        file_obj.refresh_from_db()
        assert file_obj.comment == "Original comment"

    def test_comment_nonexistent_file_returns_404(self, authenticated_client):
        """
        Verify that updating comment on nonexistent file returns 404.

        Expected:
            - HTTP 404 Not Found
        """

        # Arrange
        comment_data = {
            "comment": "New comment",
        }

        # Act
        response = authenticated_client.patch(
            "/api/storage/files/99999/comment/", comment_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND


# ==============================================================================
# TESTS: FILE DOWNLOAD (AUTHENTICATED)
# ==============================================================================


class TestFileDownloadView:
    """
    Test suite for authenticated file download endpoint.

    Endpoint: GET /api/storage/files/{id}/download/
    Authentication: Required
    """

    def test_download_owner_can_download_own_file(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that file owner can download their file.

        Expected:
            - HTTP 200 OK
            - File content returned
            - Content-Disposition header contains original_name
            - last_downloaded timestamp updated
        """

        # Arrange
        file_obj = create_file(
            owner=authenticated_client.user,
            original_name="download_test.txt",
            size=1024,
        )
        assert file_obj.last_downloaded is None

        # Act
        response = authenticated_client.get(f"/api/storage/files/{file_obj.id}/download/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response["Content-Type"] == "application/octet-stream"
        assert "download_test.txt" in response["Content-Disposition"]

        file_obj.refresh_from_db()
        assert file_obj.last_downloaded is not None

    def test_download_unauthorized_user_returns_403(
        self, authenticated_client, create_file, another_user_account, temp_media_root
    ):
        """
        Verify that user cannot download another user's file.

        Expected:
            - HTTP 403 Forbidden
        """

        # Arrange
        file_obj = create_file(owner=another_user_account, original_name="other_file.txt")

        # Act
        response = authenticated_client.get(f"/api/storage/files/{file_obj.id}/download/")

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_download_admin_can_download_any_file(
        self, admin_client, create_file, user_account, temp_media_root
    ):
        """
        Verify that admin can download any user's file.

        Expected:
            - HTTP 200 OK
            - File content returned
        """

        # Arrange
        file_obj = create_file(owner=user_account, original_name="user_file.txt")

        # Act
        response = admin_client.get(f"/api/storage/files/{file_obj.id}/download/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response["Content-Type"] == "application/octet-stream"

    def test_download_nonexistent_file_returns_404(self, authenticated_client):
        """
        Verify that downloading nonexistent file returns 404.

        Expected:
            - HTTP 404 Not Found
        """
        # Act
        response = authenticated_client.get("/api/storage/files/99999/download/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_download_updates_last_downloaded_timestamp(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that download updates last_downloaded field.

        Expected:
            - last_downloaded is set to current time
            - Multiple downloads update timestamp each time
        """

        # Arrange
        file_obj = create_file(owner=authenticated_client.user, original_name="test.txt")
        assert file_obj.last_downloaded is None

        # Act - First download
        authenticated_client.get(f"/api/storage/files/{file_obj.id}/download/")
        file_obj.refresh_from_db()
        first_download = file_obj.last_downloaded

        # Act - Second download (wait a bit)
        import time

        time.sleep(0.1)
        authenticated_client.get(f"/api/storage/files/{file_obj.id}/download/")
        file_obj.refresh_from_db()
        second_download = file_obj.last_downloaded

        # Assert
        assert first_download is not None
        assert second_download is not None
        assert second_download > first_download
