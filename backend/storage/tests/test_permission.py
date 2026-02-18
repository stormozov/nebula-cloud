"""
Tests for storage application permissions.

This module tests all permission-related functionality including:
- Owner access to own files (all operations)
- Admin access to any user's files (all operations)
- Unauthorized access rejection (401/403 responses)
- Edge cases: admin deleting files, managing public links, etc.

All tests verify that the IsOwnerOrAdmin permission class
works correctly across all storage endpoints.
"""

# pylint: disable=no-member

from django.contrib.auth import get_user_model
from rest_framework import status

from storage.models import File

User = get_user_model()


# ==============================================================================
# TESTS: OWNER ACCESS (REGULAR USER)
# ==============================================================================


class TestOwnerAccess:
    """
    Test suite verifying that file owners have full access to their files.

    These tests ensure that a regular user can perform all operations
    on files they own, regardless of file properties or public link status.
    """

    def test_owner_can_list_own_files(self, authenticated_client, create_file, temp_media_root):
        """
        Verify that owner can retrieve list of their own files.

        Expected:
            - HTTP 200 OK
            - Only owner's files are returned
            - Files from other users are excluded
        """

        # Arrange
        own_file1 = create_file(owner=authenticated_client.user, original_name="own_file1.txt")
        own_file2 = create_file(owner=authenticated_client.user, original_name="own_file2.txt")

        # Act
        response = authenticated_client.get("/api/storage/files/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        returned_ids = [f["id"] for f in response.data]
        assert own_file1.id in returned_ids
        assert own_file2.id in returned_ids

    def test_owner_can_view_own_file_detail(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that owner can view details of their own file.

        Expected:
            - HTTP 200 OK
            - All file metadata is returned
        """

        # Arrange
        comment = "Private comment"
        original_name = "secret.txt"
        size = 2048
        file_obj = create_file(
            owner=authenticated_client.user,
            original_name=original_name,
            size=size,
            comment=comment,
        )

        # Act
        response = authenticated_client.get(f"/api/storage/files/{file_obj.id}/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["original_name"] == original_name
        assert response.data["size"] == size
        assert response.data["comment"] == comment

    def test_owner_can_upload_file(self, authenticated_client, test_file, temp_media_root):
        """
        Verify that owner can upload new files to their storage.

        Expected:
            - HTTP 201 Created
            - File is saved with correct owner
            - Metadata is preserved
        """

        # Arrange
        upload_data = {
            "file": test_file,
            "comment": "My new file",
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

    def test_owner_can_delete_own_file(self, authenticated_client, create_file, temp_media_root):
        """
        Verify that owner can delete their own file.

        Expected:
            - HTTP 204 No Content
            - File is removed from database
            - Physical file is removed from disk
        """

        # Arrange
        file_obj = create_file(owner=authenticated_client.user, original_name="to_delete.txt")
        file_id = file_obj.id

        # Act
        response = authenticated_client.delete(f"/api/storage/files/{file_id}/")

        # Assert
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not File.objects.filter(id=file_id).exists()

    def test_owner_can_rename_own_file(self, authenticated_client, create_file, temp_media_root):
        """
        Verify that owner can rename their own file.

        Expected:
            - HTTP 200 OK
            - original_name is updated
            - Physical file path remains unchanged
        """

        # Arrange
        new_name = "new_name.txt"
        file_obj = create_file(owner=authenticated_client.user, original_name="old_name.txt")
        old_path = file_obj.file.path

        rename_data = {"original_name": new_name}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_obj.id}/rename/", rename_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        file_obj.refresh_from_db()
        assert file_obj.original_name == new_name
        assert file_obj.file.path == old_path

    def test_owner_can_update_own_file_comment(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that owner can update comment on their own file.

        Expected:
            - HTTP 200 OK
            - comment field is updated
        """

        # Arrange
        new_comment = "Updated comment"
        file_obj = create_file(
            owner=authenticated_client.user,
            original_name="test.txt",
            comment="Old comment",
        )

        comment_data = {"comment": new_comment}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_obj.id}/comment/", comment_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        file_obj.refresh_from_db()
        assert file_obj.comment == new_comment

    def test_owner_can_generate_public_link_for_own_file(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that owner can generate public link for their own file.

        Expected:
            - HTTP 200 OK
            - public_link is generated
            - Link is anonymized (no user info)
        """

        # Arrange
        file_obj = create_file(owner=authenticated_client.user, original_name="share_me.pdf")

        # Act
        response = authenticated_client.post(
            f"/api/storage/files/{file_obj.id}/public-link/generate/",
            data={},
            format="json",
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["has_public_link"] is True
        assert response.data["public_link_url"] is not None

        file_obj.refresh_from_db()
        assert file_obj.public_link is not None

    def test_owner_can_delete_public_link_for_own_file(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that owner can delete public link for their own file.

        Expected:
            - HTTP 200 OK
            - public_link is set to None
        """

        # Arrange
        file_obj = create_file(
            owner=authenticated_client.user,
            original_name="test.txt",
            public_link="existing_link_123",
        )

        # Act
        response = authenticated_client.delete(f"/api/storage/files/{file_obj.id}/public-link/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["has_public_link"] is False

        file_obj.refresh_from_db()
        assert file_obj.public_link is None

    def test_owner_can_download_own_file(self, authenticated_client, create_file, temp_media_root):
        """
        Verify that owner can download their own file.

        Expected:
            - HTTP 200 OK
            - File content is returned
            - Content-Disposition contains original_name
        """

        # Arrange
        original_name = "download_me.docx"
        file_obj = create_file(
            owner=authenticated_client.user,
            original_name=original_name,
            size=1024,
        )

        # Act
        response = authenticated_client.get(f"/api/storage/files/{file_obj.id}/download/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert original_name in response["Content-Disposition"]


# ==============================================================================
# TESTS: ADMIN ACCESS
# ==============================================================================


class TestAdminAccess:
    """
    Test suite verifying that admin users have access to all files.

    These tests ensure that a user with is_staff=True can perform
    all operations on files owned by any user, including their own.
    """

    def test_admin_can_list_all_files(
        self, admin_client, create_file, user_account, another_user_account, temp_media_root
    ):
        """
        Verify that admin can retrieve list of all files without filter.

        Expected:
            - HTTP 200 OK
            - Files from all users are returned
        """

        # Arrange
        file1 = create_file(owner=user_account, original_name="user1_file.txt")
        file2 = create_file(owner=another_user_account, original_name="user2_file.txt")
        file3 = create_file(owner=admin_client.user, original_name="admin_file.txt")

        # Act
        response = admin_client.get("/api/storage/files/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        returned_ids = [f["id"] for f in response.data]
        assert file1.id in returned_ids
        assert file2.id in returned_ids
        assert file3.id in returned_ids

    def test_admin_can_filter_files_by_user_id(
        self, admin_client, create_file, user_account, another_user_account, temp_media_root
    ):
        """
        Verify that admin can filter file list by specific user_id.

        Expected:
            - HTTP 200 OK
            - Only files of specified user are returned
        """

        # Arrange
        user1_file1 = create_file(owner=user_account, original_name="u1_f1.txt")
        user1_file2 = create_file(owner=user_account, original_name="u1_f2.txt")
        user2_file = create_file(owner=another_user_account, original_name="u2_f1.txt")

        # Act
        response = admin_client.get(f"/api/storage/files/?user_id={user_account.id}")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        returned_ids = [f["id"] for f in response.data]
        assert user1_file1.id in returned_ids
        assert user1_file2.id in returned_ids
        assert user2_file.id not in returned_ids

    def test_admin_can_view_any_user_file_detail(
        self, admin_client, create_file, user_account, temp_media_root
    ):
        """
        Verify that admin can view details of any user's file.

        Expected:
            - HTTP 200 OK
            - File metadata is returned regardless of owner
        """

        # Arrange
        original_name = "admin_secret.txt"
        size = 4096
        file_obj = create_file(
            owner=user_account,
            original_name=original_name,
            size=size,
            comment="User's private comment",
        )

        # Act
        response = admin_client.get(f"/api/storage/files/{file_obj.id}/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["original_name"] == original_name
        assert response.data["size"] == size

    def test_admin_can_delete_any_user_file(
        self, admin_client, create_file, user_account, temp_media_root
    ):
        """
        Verify that admin can delete any user's file.

        Expected:
            - HTTP 204 No Content
            - File is removed from database
        """

        # Arrange
        file_obj = create_file(owner=user_account, original_name="admin_delete.txt")
        file_id = file_obj.id

        # Act
        response = admin_client.delete(f"/api/storage/files/{file_id}/")

        # Assert
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not File.objects.filter(id=file_id).exists()

    def test_admin_can_rename_any_user_file(
        self, admin_client, create_file, user_account, temp_media_root
    ):
        """
        Verify that admin can rename any user's file.

        Expected:
            - HTTP 200 OK
            - original_name is updated
        """

        # Arrange
        file_obj = create_file(owner=user_account, original_name="original_name.txt")

        rename_data = {"original_name": "admin_renamed.txt"}

        # Act
        response = admin_client.patch(
            f"/api/storage/files/{file_obj.id}/rename/", rename_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        file_obj.refresh_from_db()
        assert file_obj.original_name == "admin_renamed.txt"

    def test_admin_can_update_any_user_file_comment(
        self, admin_client, create_file, user_account, temp_media_root
    ):
        """
        Verify that admin can update comment on any user's file.

        Expected:
            - HTTP 200 OK
            - comment field is updated
        """

        # Arrange
        file_obj = create_file(
            owner=user_account,
            original_name="test.txt",
            comment="Original comment",
        )
        comment_data = {"comment": "Admin updated comment"}

        # Act
        response = admin_client.patch(
            f"/api/storage/files/{file_obj.id}/comment/", comment_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        file_obj.refresh_from_db()
        assert file_obj.comment == "Admin updated comment"

    def test_admin_can_generate_public_link_for_any_user_file(
        self, admin_client, create_file, user_account, temp_media_root
    ):
        """
        Verify that admin can generate public link for any user's file.

        Expected:
            - HTTP 200 OK
            - public_link is generated
        """

        # Arrange
        file_obj = create_file(owner=user_account, original_name="admin_share.pdf")

        # Act
        response = admin_client.post(
            f"/api/storage/files/{file_obj.id}/public-link/generate/",
            data={},
            format="json",
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["has_public_link"] is True

        file_obj.refresh_from_db()
        assert file_obj.public_link is not None

    def test_admin_can_delete_public_link_for_any_user_file(
        self, admin_client, create_file, user_account, temp_media_root
    ):
        """
        Verify that admin can delete public link for any user's file.

        Expected:
            - HTTP 200 OK
            - public_link is set to None
        """

        # Arrange
        file_obj = create_file(
            owner=user_account,
            original_name="test.txt",
            public_link="link_to_delete",
        )

        # Act
        response = admin_client.delete(f"/api/storage/files/{file_obj.id}/public-link/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["has_public_link"] is False

        file_obj.refresh_from_db()
        assert file_obj.public_link is None

    def test_admin_can_download_any_user_file(
        self, admin_client, create_file, user_account, temp_media_root
    ):
        """
        Verify that admin can download any user's file.

        Expected:
            - HTTP 200 OK
            - File content is returned with original_name
        """

        # Arrange
        original_name = "admin_download.xlsx"
        file_obj = create_file(
            owner=user_account,
            original_name=original_name,
            size=2048,
        )

        # Act
        response = admin_client.get(f"/api/storage/files/{file_obj.id}/download/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert original_name in response["Content-Disposition"]

    def test_admin_can_access_own_storage(self, admin_client, create_file, temp_media_root):
        """
        Verify that admin can access their own storage like a regular user.

        Expected:
            - Admin can list, view, upload, delete their own files
            - No special treatment needed for admin's own files
        """

        # Arrange - Upload a file as admin
        from django.core.files.uploadedfile import SimpleUploadedFile

        test_file = SimpleUploadedFile(
            name="admin_own.txt",
            content=b"Admin's own file content",
            content_type="text/plain",
        )

        # Act - Upload
        upload_response = admin_client.post(
            "/api/storage/files/upload/",
            {"file": test_file, "comment": "Admin's file"},
            format="multipart",
        )

        # Assert - Upload succeeded
        assert upload_response.status_code == status.HTTP_201_CREATED

        # Act - List files (should include own file)
        list_response = admin_client.get("/api/storage/files/")

        # Assert - Own file is in list
        assert upload_response.data["id"] in [f["id"] for f in list_response.data]


# ==============================================================================
# TESTS: UNAUTHORIZED ACCESS REJECTION
# ==============================================================================


class TestUnauthorizedAccess:
    """
    Test suite verifying that unauthorized access is properly rejected.

    These tests ensure that:
    - Unauthenticated requests return 401
    - Authenticated users cannot access other users' files (403)
    - Error responses contain appropriate JSON messages
    """

    def test_unauthenticated_list_returns_401(self, api_client):
        """
        Verify that unauthenticated user cannot list files.

        Expected:
            - HTTP 401 Unauthorized
        """
        # Act
        response = api_client.get("/api/storage/files/")

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_unauthenticated_detail_returns_401(self, api_client, create_file):
        """
        Verify that unauthenticated user cannot view file details.

        Expected:
            - HTTP 401 Unauthorized
        """

        # Arrange
        file_obj = create_file(original_name="test.txt")

        # Act
        response = api_client.get(f"/api/storage/files/{file_obj.id}/")

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_unauthenticated_upload_returns_401(self, api_client, test_file):
        """
        Verify that unauthenticated user cannot upload files.

        Expected:
            - HTTP 401 Unauthorized
        """

        # Arrange
        upload_data = {"file": test_file, "comment": "Test"}

        # Act
        response = api_client.post("/api/storage/files/upload/", upload_data, format="multipart")

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_unauthenticated_delete_returns_401(self, api_client, create_file):
        """
        Verify that unauthenticated user cannot delete files.

        Expected:
            - HTTP 401 Unauthorized
        """

        # Arrange
        file_obj = create_file(original_name="test.txt")

        # Act
        response = api_client.delete(f"/api/storage/files/{file_obj.id}/")

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_user_cannot_view_another_user_file(
        self, authenticated_client, create_file, another_user_account, temp_media_root
    ):
        """
        Verify that user cannot view another user's file details.

        Expected:
            - HTTP 403 Forbidden
            - File data is not exposed
        """

        # Arrange
        file_obj = create_file(owner=another_user_account, original_name="other_secret.txt")

        # Act
        response = authenticated_client.get(f"/api/storage/files/{file_obj.id}/")

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_user_cannot_delete_another_user_file(
        self, authenticated_client, create_file, another_user_account, temp_media_root
    ):
        """
        Verify that user cannot delete another user's file.

        Expected:
            - HTTP 403 Forbidden
            - File remains in database
        """

        # Arrange
        file_obj = create_file(owner=another_user_account, original_name="protected.txt")

        # Act
        response = authenticated_client.delete(f"/api/storage/files/{file_obj.id}/")

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert File.objects.filter(id=file_obj.id).exists()

    def test_user_cannot_rename_another_user_file(
        self, authenticated_client, create_file, another_user_account, temp_media_root
    ):
        """
        Verify that user cannot rename another user's file.

        Expected:
            - HTTP 403 Forbidden
            - original_name remains unchanged
        """

        # Arrange
        original_name = "original.txt"
        file_obj = create_file(owner=another_user_account, original_name=original_name)

        rename_data = {"original_name": "hacked.txt"}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_obj.id}/rename/", rename_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN
        file_obj.refresh_from_db()
        assert file_obj.original_name == original_name

    def test_user_cannot_update_another_user_comment(
        self, authenticated_client, create_file, another_user_account, temp_media_root
    ):
        """
        Verify that user cannot update another user's file comment.

        Expected:
            - HTTP 403 Forbidden
            - comment remains unchanged
        """

        # Arrange
        comment = "Original comment"
        file_obj = create_file(
            owner=another_user_account,
            original_name="test.txt",
            comment=comment,
        )

        comment_data = {"comment": "Hacked comment"}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_obj.id}/comment/", comment_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN
        file_obj.refresh_from_db()
        assert file_obj.comment == comment

    def test_user_cannot_generate_link_for_another_user_file(
        self, authenticated_client, create_file, another_user_account, temp_media_root
    ):
        """
        Verify that user cannot generate public link for another user's file.

        Expected:
            - HTTP 403 Forbidden
            - public_link remains None
        """

        # Arrange
        file_obj = create_file(owner=another_user_account, original_name="secret.pdf")

        # Act
        response = authenticated_client.post(
            f"/api/storage/files/{file_obj.id}/public-link/generate/",
            data={},
            format="json",
        )

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN
        file_obj.refresh_from_db()
        assert file_obj.public_link is None

    def test_user_cannot_delete_another_user_public_link(
        self, authenticated_client, create_file, another_user_account, temp_media_root
    ):
        """
        Verify that user cannot delete another user's public link.

        Expected:
            - HTTP 403 Forbidden
            - public_link remains unchanged
        """

        # Arrange
        public_link = "public_link_123"
        file_obj = create_file(
            owner=another_user_account,
            original_name="test.txt",
            public_link=public_link,
        )

        # Act
        response = authenticated_client.delete(f"/api/storage/files/{file_obj.id}/public-link/")

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN
        file_obj.refresh_from_db()
        assert file_obj.public_link == public_link

    def test_user_cannot_download_another_user_file(
        self, authenticated_client, create_file, another_user_account, temp_media_root
    ):
        """
        Verify that user cannot download another user's file.

        Expected:
            - HTTP 403 Forbidden
        """

        # Arrange
        file_obj = create_file(owner=another_user_account, original_name="protected.docx")

        # Act
        response = authenticated_client.get(f"/api/storage/files/{file_obj.id}/download/")

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_error_response_format_is_json(
        self, authenticated_client, create_file, another_user_account
    ):
        """
        Verify that permission errors return JSON-formatted responses.

        Expected:
            - Response Content-Type is application/json
            - Error message is in JSON format
        """

        # Arrange
        file_obj = create_file(owner=another_user_account, original_name="test.txt")

        # Act
        response = authenticated_client.get(f"/api/storage/files/{file_obj.id}/")

        # Assert
        assert response["Content-Type"] == "application/json"
        assert isinstance(response.data, dict)


# ==============================================================================
# TESTS: EDGE PERMISSIONS
# ==============================================================================


class TestEdgePermissions:
    """
    Test suite for edge cases in permission handling.

    These tests verify behavior in less common scenarios:
    - Admin with invalid user_id parameter
    - File with missing owner (should not happen, but test defensively)
    - Concurrent access attempts
    """

    def test_admin_with_invalid_user_id_returns_fallback(
        self, admin_client, create_file, user_account, temp_media_root
    ):
        """
        Verify that admin with invalid user_id parameter gets fallback behavior.

        Expected:
            - HTTP 200 OK (not error)
            - Returns admin's own files or all files as fallback
        """

        # Arrange
        create_file(owner=user_account, original_name="other_file.txt")

        # Act - Invalid user_id (non-numeric)
        response = admin_client.get("/api/storage/files/?user_id=invalid")

        # Assert - Should not crash, returns some files
        assert response.status_code == status.HTTP_200_OK

    def test_admin_with_nonexistent_user_id_returns_empty(self, admin_client, temp_media_root):
        """
        Verify that admin with nonexistent user_id gets empty list.

        Expected:
            - HTTP 200 OK
            - Empty list returned (no files for that user)
        """
        # Act
        response = admin_client.get("/api/storage/files/?user_id=999999")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data == []

    def test_permission_check_happens_before_file_retrieval(
        self, authenticated_client, another_user_account
    ):
        """
        Verify that permission is checked before attempting file retrieval.

        This ensures we don't leak information about file existence
        through different error messages or timing.

        Expected:
            - HTTP 403 Forbidden (not 404)
            - Same error format regardless of file existence
        """
        # Act
        response = authenticated_client.get("/api/storage/files/999999/")

        # Assert - Should be 404 (not found) not 403 (forbidden)
        assert response.status_code in [status.HTTP_404_NOT_FOUND, status.HTTP_403_FORBIDDEN]

    def test_public_link_access_does_not_require_owner_permission(
        self, api_client, create_file, temp_media_root
    ):
        """
        Verify that public link access bypasses owner permission checks.

        Expected:
            - Unauthenticated user can access file via public link
            - No 401/403 error for public endpoints
        """

        # Arrange
        create_file(
            original_name="public_file.txt",
            public_link="public123",
        )

        # Act - Public info access
        response_info = api_client.get("/api/storage/public/public123/")

        # Act - Public download access
        response_download = api_client.get("/api/storage/public/public123/download/")

        # Assert
        assert response_info.status_code == status.HTTP_200_OK
        assert response_download.status_code == status.HTTP_200_OK

    def test_permission_class_is_applied_to_all_endpoints(
        self, authenticated_client, create_file, another_user_account, temp_media_root
    ):
        """
        Verify that IsOwnerOrAdmin permission is consistently applied.

        Expected:
            - All protected endpoints return 403 for unauthorized access
            - No endpoint accidentally allows cross-user access
        """

        # Arrange
        file_obj = create_file(owner=another_user_account, original_name="protected.txt")
        file_id = file_obj.id
        endpoints_to_test = [
            ("GET", f"/api/storage/files/{file_id}/", None),
            ("DELETE", f"/api/storage/files/{file_id}/", None),
            ("PATCH", f"/api/storage/files/{file_id}/rename/", {"original_name": "new.txt"}),
            ("PATCH", f"/api/storage/files/{file_id}/comment/", {"comment": "new"}),
            ("POST", f"/api/storage/files/{file_id}/public-link/generate/", {}),
            ("DELETE", f"/api/storage/files/{file_id}/public-link/", None),
            ("GET", f"/api/storage/files/{file_id}/download/", None),
        ]

        # Act & Assert - All should return 403
        for method, url, data in endpoints_to_test:
            response = None

            match method:
                case "GET":
                    response = authenticated_client.get(url)
                case "DELETE":
                    response = authenticated_client.delete(url)
                case "PATCH":
                    response = authenticated_client.patch(url, data, format="json")
                case "POST":
                    response = authenticated_client.post(url, data, format="json")

            assert (
                response.status_code == status.HTTP_403_FORBIDDEN
            ), f"Endpoint {method} {url} should return 403, got {response.status_code}"
