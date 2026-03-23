"""
Pytest tests for FileViewSet.

This module contains comprehensive tests for all FileViewSet actions:
- Standard CRUD operations (list, retrieve, create, update, destroy)
- Custom actions (upload, download, rename, comment)
- Permission and access control tests
"""

# pylint: disable=unused-argument
# pylint: disable=missing-function-docstring

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient

from storage.models import File

User = get_user_model()


# ==================================================================================================
# TEST CLASS: LIST ACTION
# ==================================================================================================


class TestFileViewSetList:
    """Tests for GET /api/storage/files/ endpoint (list action)."""

    def test_list_returns_200_for_authenticated_user(
        self, authenticated_client: APIClient, create_file
    ) -> None:
        """
        Test: List files returns 200 for authenticated user.

        Scenario: Authenticated user requests their file list.
        Expected: HTTP 200 with list of user's files.
        """

        # Arrange
        create_file(owner=authenticated_client.user, original_name="doc1.txt")
        create_file(owner=authenticated_client.user, original_name="doc2.pdf")

        # Act
        response = authenticated_client.get("/api/storage/files/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) == 2

    def test_list_returns_only_user_files(
        self, authenticated_client: APIClient, create_file, another_user_account
    ) -> None:
        """
        Test: List returns only authenticated user's files.

        Scenario: User has files, another user has different files.
        Expected: Response contains only current user's files.
        """

        # Arrange
        create_file(owner=authenticated_client.user, original_name="my_file.txt")
        create_file(owner=another_user_account, original_name="other_file.txt")

        # Act
        response = authenticated_client.get("/api/storage/files/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert all(item["original_name"] != "other_file.txt" for item in response.data)

    def test_list_admin_filter_by_user_id(
        self, admin_client: APIClient, create_file, user_account, another_user_account
    ) -> None:
        """
        Test: Admin can filter files by user_id parameter.

        Scenario: Admin requests files with user_id query param.
        Expected: HTTP 200 with only specified user's files.
        """

        # Arrange
        create_file(owner=user_account, original_name="user1_file.txt")
        create_file(owner=another_user_account, original_name="user2_file.txt")

        # Act
        response = admin_client.get(f"/api/storage/files/?user_id={user_account.id}")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert all(item["original_name"] == "user1_file.txt" for item in response.data)

    def test_list_empty_returns_empty_array(self, authenticated_client: APIClient) -> None:
        """
        Test: List returns empty array when no files exist.

        Scenario: Authenticated user with no uploaded files requests list.
        Expected: HTTP 200 with empty array.
        """

        # Arrange
        # No files created for this user

        # Act
        response = authenticated_client.get("/api/storage/files/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data == []


# ==================================================================================================
# TEST CLASS: RETRIEVE ACTION
# ==================================================================================================


class TestFileViewSetRetrieve:
    """Tests for GET /api/storage/files/{id}/ endpoint (retrieve action)."""

    def test_retrieve_returns_200_with_file_data(
        self, authenticated_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Retrieve returns 200 with file metadata.

        Scenario: User requests details of their own file.
        Expected: HTTP 200 with complete file data.
        """

        # Arrange
        file_id = uploaded_file.id

        # Act
        response = authenticated_client.get(f"/api/storage/files/{file_id}/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["id"] == file_id
        assert response.data["original_name"] == uploaded_file.original_name

    def test_retrieve_returns_404_for_nonexistent_file(
        self, authenticated_client: APIClient
    ) -> None:
        """
        Test: Retrieve returns 404 for invalid file ID.

        Scenario: User requests details of non-existent file.
        Expected: HTTP 404 Not Found.
        """

        # Arrange
        nonexistent_id = 99999

        # Act
        response = authenticated_client.get(f"/api/storage/files/{nonexistent_id}/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_retrieve_admin_can_access_any_file(
        self, admin_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Admin can retrieve any user's file.

        Scenario: Admin requests details of regular user's file.
        Expected: HTTP 200 with file data.
        """

        # Arrange
        file_id = uploaded_file.id

        # Act
        response = admin_client.get(f"/api/storage/files/{file_id}/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["id"] == file_id


# ==================================================================================================
# TEST CLASS: CREATE ACTION
# ==================================================================================================


class TestFileViewSetCreate:
    """Tests for POST /api/storage/files/ endpoint (create action)."""

    def test_create_returns_201_with_uploaded_file(
        self, authenticated_client: APIClient, test_file
    ) -> None:
        """
        Test: Create returns 201 with new file data.

        Scenario: User uploads valid file via standard create endpoint.
        Expected: HTTP 201 Created with serialized file data.
        """

        # Arrange
        upload_data = {"file": test_file, "comment": "Test upload"}

        # Act
        response = authenticated_client.post("/api/storage/files/", upload_data, format="multipart")

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data["original_name"] == "test_file.txt"

    def test_create_sets_owner_to_authenticated_user(
        self, authenticated_client: APIClient, test_file
    ) -> None:
        """
        Test: Create sets file owner to authenticated user.

        Scenario: User uploads file, ownership is assigned automatically.
        Expected: File.owner equals request.user.
        """

        # Arrange
        upload_data = {"file": test_file}
        user = authenticated_client.user

        # Act
        response = authenticated_client.post("/api/storage/files/", upload_data, format="multipart")
        created_file = File.objects.get(id=response.data["id"])  # pylint: disable=no-member

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        assert created_file.owner == user

    def test_create_without_file_field_returns_400(self, authenticated_client: APIClient) -> None:
        """
        Test: Create returns 400 when file field is missing.

        Scenario: User sends request without 'file' in multipart data.
        Expected: HTTP 400 Bad Request with validation error.
        """

        # Arrange
        upload_data = {"comment": "No file attached"}

        # Act
        response = authenticated_client.post("/api/storage/files/", upload_data, format="multipart")

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST


# ==================================================================================================
# TEST CLASS: UPDATE ACTIONS
# ==================================================================================================


class TestFileViewSetUpdate:
    """Tests for PUT/PATCH /api/storage/files/{id}/ endpoints."""

    def test_partial_update_renames_file(
        self, authenticated_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Partial update changes file original_name.

        Scenario: User patches file with new original_name.
        Expected: HTTP 200 with updated name.
        """

        # Arrange
        file_id = uploaded_file.id
        new_name = "renamed_document.pdf"
        update_data = {"original_name": new_name}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_id}/", update_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["original_name"] == new_name

    def test_partial_update_changes_comment(
        self, authenticated_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Partial update changes file comment.

        Scenario: User patches file with new comment.
        Expected: HTTP 200 with updated comment.
        """

        # Arrange
        file_id = uploaded_file.id
        new_comment = "Updated comment text"
        update_data = {"comment": new_comment}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_id}/", update_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == new_comment

    def test_full_update_returns_200(
        self, authenticated_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Full update (PUT) returns 200 with updated data.

        Scenario: User sends complete file data via PUT request.
        Expected: HTTP 200 with fully updated file representation.
        """

        # Arrange
        file_id = uploaded_file.id
        new_name = "full_update.txt"
        update_data = {
            "original_name": new_name,
            "comment": "Full update comment",
        }

        # Act
        response = authenticated_client.put(
            f"/api/storage/files/{file_id}/", update_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["original_name"] == new_name


# ==================================================================================================
# TEST CLASS: DESTROY ACTION
# ==================================================================================================


class TestFileViewSetDestroy:
    """Tests for DELETE /api/storage/files/{id}/ endpoint."""

    def test_destroy_returns_204_and_deletes_file(
        self, authenticated_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Destroy returns 204 and removes file from database.

        Scenario: User deletes their own file.
        Expected: HTTP 204 No Content, file no longer exists.
        """

        # Arrange
        file_id = uploaded_file.id

        # Act
        response = authenticated_client.delete(f"/api/storage/files/{file_id}/")

        # Assert
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not File.objects.filter(id=file_id).exists()  # pylint: disable=no-member

    def test_destroy_nonexistent_file_returns_404(self, authenticated_client: APIClient) -> None:
        """
        Test: Destroy returns 404 for non-existent file.

        Scenario: User attempts to delete file with invalid ID.
        Expected: HTTP 404 Not Found.
        """

        # Arrange
        nonexistent_id = 99999

        # Act
        response = authenticated_client.delete(f"/api/storage/files/{nonexistent_id}/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND


# ==================================================================================================
# TEST CLASS: UPLOAD ACTION
# ==================================================================================================


class TestFileViewSetUploadAction:
    """Tests for POST /api/storage/files/upload/ custom action."""

    def test_upload_action_returns_201_with_file(
        self, authenticated_client: APIClient, test_file
    ) -> None:
        """
        Test: Upload action returns 201 with uploaded file data.

        Scenario: User uploads file via custom /upload/ endpoint.
        Expected: HTTP 201 Created with serialized file.
        """

        # Arrange
        file_name = "test_file.txt"
        upload_data = {"file": test_file, "comment": "Via upload action"}

        # Act
        response = authenticated_client.post(
            "/api/storage/files/upload/", upload_data, format="multipart"
        )

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data["original_name"] == file_name


# ==================================================================================================
# TEST CLASS: DOWNLOAD ACTION
# ==================================================================================================


class TestFileViewSetDownloadAction:
    """Tests for GET /api/storage/files/{id}/download/ custom action."""

    def test_download_returns_file_response(
        self, authenticated_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Download action returns FileResponse with correct headers.

        Scenario: User downloads their own file via /download/ endpoint.
        Expected: HTTP 200 with FileResponse, correct Content-Disposition.
        """

        # Arrange
        file_id = uploaded_file.id
        http_header = "Content-Disposition"

        # Act
        response = authenticated_client.get(f"/api/storage/files/{file_id}/download/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response[http_header].startswith("attachment")
        assert uploaded_file.original_name in response[http_header]

    def test_download_updates_last_downloaded_timestamp(
        self, authenticated_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Download action updates file's last_downloaded field.

        Scenario: User downloads file, timestamp should be updated.
        Expected: last_downloaded is not None and recent.
        """

        # Arrange
        file_id = uploaded_file.id
        uploaded_file.last_downloaded = None
        uploaded_file.save(update_fields=["last_downloaded"])

        # Act
        authenticated_client.get(f"/api/storage/files/{file_id}/download/")
        uploaded_file.refresh_from_db()

        # Assert
        assert uploaded_file.last_downloaded is not None

    def test_download_nonexistent_file_returns_404(self, authenticated_client: APIClient) -> None:
        """
        Test: Download returns 404 for non-existent file.

        Scenario: User requests download of invalid file ID.
        Expected: HTTP 404 Not Found.
        """

        # Arrange
        nonexistent_id = 99999

        # Act
        response = authenticated_client.get(f"/api/storage/files/{nonexistent_id}/download/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND


# ==================================================================================================
# TEST CLASS: RENAME ACTION
# ==================================================================================================


class TestFileViewSetRenameAction:
    """Tests for PATCH /api/storage/files/{id}/rename/ custom action."""

    def test_rename_returns_200_with_new_name(
        self, authenticated_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Rename action returns 200 with updated original_name.

        Scenario: User renames their file via /rename/ endpoint.
        Expected: HTTP 200 with new name in response.
        """

        # Arrange
        file_id = uploaded_file.id
        new_name = "new_name_2024.txt"
        rename_data = {"original_name": new_name}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_id}/rename/", rename_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["original_name"] == new_name

    def test_rename_invalid_name_returns_400(
        self, authenticated_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Rename returns 400 for invalid filename.

        Scenario: User attempts to rename file with forbidden characters.
        Expected: HTTP 400 Bad Request with validation error.
        """

        # Arrange
        file_id = uploaded_file.id
        invalid_name = "file/with/slashes.txt"
        rename_data = {"original_name": invalid_name}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_id}/rename/", rename_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "original_name" in response.data or "detail" in response.data


# ==================================================================================================
# TEST CLASS: COMMENT ACTION
# ==================================================================================================


class TestFileViewSetCommentAction:
    """Tests for PATCH /api/storage/files/{id}/comment/ custom action."""

    def test_comment_update_returns_200_with_new_comment(
        self, authenticated_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Comment action returns 200 with updated comment.

        Scenario: User updates comment via /comment/ endpoint.
        Expected: HTTP 200 with new comment in response.
        """

        # Arrange
        file_id = uploaded_file.id
        new_comment = "This is an updated comment"
        comment_data = {"comment": new_comment}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_id}/comment/", comment_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == new_comment

    def test_comment_clear_with_empty_string(
        self, authenticated_client: APIClient, uploaded_file: File
    ) -> None:
        """
        Test: Comment action clears comment when empty string provided.

        Scenario: User sends empty comment to clear existing comment.
        Expected: HTTP 200 with empty comment field.
        """

        # Arrange
        file_id = uploaded_file.id
        uploaded_file.comment = "Existing comment"
        uploaded_file.save(update_fields=["comment"])
        clear_data = {"comment": ""}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_id}/comment/", clear_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == ""
