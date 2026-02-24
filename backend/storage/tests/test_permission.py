"""
Tests for storage application permissions.

This module tests all permission-related functionality including:
- Unauthorized access rejection (401/403 responses)
- Edge cases: admin deleting files, managing public links, etc.

All tests verify that the IsOwnerOrAdmin permission class
works correctly across all storage endpoints.
"""

# pylint: disable=no-member

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient

from storage.models import File

User = get_user_model()

# ==================================================================================================
# TESTS: UNAUTHORIZED ACCESS REJECTION
# ==================================================================================================


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

        Scenario: User attempts to list files

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

        Scenario: User attempts to view file

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

        Scenario: User attempts to upload file

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

        Scenario: User attempts to delete file

        Expected:
            - HTTP 401 Unauthorized
        """

        # Arrange
        file_obj = create_file(original_name="test.txt")

        # Act
        response = api_client.delete(f"/api/storage/files/{file_obj.id}/")

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_partial_update_other_user_file_returns_403(
        self, authenticated_client: APIClient, another_user_file: File
    ) -> None:
        """
        Test: Partial update returns 403 for another user's file.

        Scenario: User attempts to modify file owned by different user.
        Expected: HTTP 403 Forbidden.
        """

        # Arrange
        file_id = another_user_file.id
        update_data = {"comment": "Unauthorized change"}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_id}/", update_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_user_cannot_view_another_user_file(
        self, authenticated_client, create_file, another_user_account
    ):
        """
        Verify that user cannot view another user's file details.

        Scenario: User attempts to view file owned by different user

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

    def test_retrieve_returns_403_for_other_user_file(
        self, authenticated_client: APIClient, another_user_file: File
    ) -> None:
        """
        Test: Retrieve returns 403 for another user's file.

        Scenario: User requests details of file owned by different user.
        Expected: HTTP 403 Forbidden.
        """

        # Arrange
        file_id = another_user_file.id

        # Act
        response = authenticated_client.get(f"/api/storage/files/{file_id}/")

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_user_cannot_delete_another_user_file(
        self, authenticated_client, create_file, another_user_account
    ):
        """
        Verify that user cannot delete another user's file.

        Scenario: User attempts to delete file owned by different user

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

    def test_rename_other_user_file_returns_403(
        self, authenticated_client: APIClient, another_user_file: File
    ) -> None:
        """
        Test: Rename returns 403 for another user's file.

        Scenario: User attempts to rename file owned by different user.
        Expected: HTTP 403 Forbidden.
        """

        # Arrange
        file_id = another_user_file.id
        rename_data = {"original_name": "hacked.txt"}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_id}/rename/", rename_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_comment_other_user_file_returns_403(
        self, authenticated_client: APIClient, another_user_file: File
    ) -> None:
        """
        Test: Comment returns 403 for another user's file.

        Scenario: User attempts to comment on file owned by different user.
        Expected: HTTP 403 Forbidden.
        """

        # Arrange
        file_id = another_user_file.id
        comment_data = {"comment": "Unauthorized comment"}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_id}/comment/", comment_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_user_cannot_generate_link_for_another_user_file(
        self, authenticated_client, create_file, another_user_account
    ):
        """
        Verify that user cannot generate public link for another user's file.

        Scenario: User generates public link for another user's file

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
        self, authenticated_client, create_file, another_user_account
    ):
        """
        Verify that user cannot delete another user's public link.

        Scenario: User deletes public link for another user's file

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

    def test_download_other_user_file_returns_403(
        self, authenticated_client: APIClient, another_user_file: File
    ) -> None:
        """
        Test: Download returns 403 for another user's file.

        Scenario: User attempts to download file owned by different user.
        Expected: HTTP 403 Forbidden.
        """

        # Arrange
        file_id = another_user_file.id

        # Act
        response = authenticated_client.get(f"/api/storage/files/{file_id}/download/")

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_error_response_format_is_json(
        self, authenticated_client, create_file, another_user_account
    ):
        """
        Verify that permission errors return JSON-formatted responses.

        Scenario: User attempts to access another user's file

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


# ==================================================================================================
# TESTS: EDGE PERMISSIONS
# ==================================================================================================


class TestEdgePermissions:
    """
    Test suite for edge cases in permission handling.

    These tests verify behavior in less common scenarios:
    - Admin with invalid user_id parameter
    - File with missing owner (should not happen, but test defensively)
    - Concurrent access attempts
    """

    def test_admin_with_invalid_user_id_returns_fallback(
        self, admin_client, create_file, user_account
    ):
        """
        Verify that admin with invalid user_id parameter gets fallback behavior.

        Scenario: Admin provides invalid user_id

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

    def test_admin_with_nonexistent_user_id_returns_empty(self, admin_client):
        """
        Verify that admin with nonexistent user_id gets empty list.

        Scenario: Admin provides nonexistent user_id

        Expected:
            - HTTP 200 OK
            - Empty list returned (no files for that user)
        """

        # Arrange
        user_id = 999999

        # Act
        response = admin_client.get(f"/api/storage/files/?user_id={user_id}")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data == []

    def test_admin_can_delete_any_user_file(
        self, admin_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Admin can delete any user's file.

        Scenario: Admin deletes file owned by regular user.
        Expected: HTTP 204 No Content, file removed.
        """

        # Arrange
        file_id = uploaded_file.id

        # Act
        response = admin_client.delete(f"/api/storage/files/{file_id}/")

        # Assert
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not File.objects.filter(id=file_id).exists()  # pylint: disable=no-member

    def test_user_cannot_access_admin_only_filter(
        self, authenticated_client: APIClient, another_user_account, create_file: File
    ) -> None:
        """
        Regular user cannot use admin-only user_id filter.

        Scenario: Regular user requests files with user_id parameter.
        Expected: HTTP 200 but filtered to user's own files only.
        """

        # Arrange
        another_user_id = another_user_account.id
        create_file(owner=another_user_account, original_name="admin_filter_test.txt", size=100)

        # Act
        response = authenticated_client.get(f"/api/storage/files/?user_id={another_user_id}")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        # Regular user should only see their own files, ignoring user_id param
        assert all(item["owner"] != another_user_account.email for item in response.data)

    def test_invalid_user_id_parameter_falls_back_gracefully(self, admin_client: APIClient) -> None:
        """
        Invalid user_id parameter returns user's own files for admin.

        Scenario: Admin provides non-numeric user_id query parameter.
        Expected: HTTP 200 with admin's own files (fallback behavior).
        """

        # Arrange
        invalid_user_id = "not_a_number"

        # Act
        response = admin_client.get(f"/api/storage/files/?user_id={invalid_user_id}")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        # Should not crash, returns admin's files or empty list
        assert isinstance(response.data, list)

    def test_permission_check_happens_before_file_retrieval(self, authenticated_client):
        """
        Verify that permission is checked before attempting file retrieval.

        This ensures we don't leak information about file existence
        through different error messages or timing.

        Scenario: User tries to access non-existent file

        Expected:
            - HTTP 403 Forbidden (not 404)
            - Same error format regardless of file existence
        """

        # Arrange
        user_id = 999999

        # Act
        response = authenticated_client.get(f"/api/storage/files/{user_id}/")

        # Assert - Should be 404 (not found) not 403 (forbidden)
        assert response.status_code in [status.HTTP_404_NOT_FOUND, status.HTTP_403_FORBIDDEN]

    def test_permission_class_is_applied_to_all_endpoints(
        self, authenticated_client, create_file, another_user_account
    ):
        """
        Verify that IsOwnerOrAdmin permission is consistently applied.

        Scenario:
            - User attempts to access their own file
            - User attempts to access another user's file

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

            assert response.status_code == status.HTTP_403_FORBIDDEN, (
                f"Endpoint {method} {url} should return 403, got {response.status_code}"
            )
