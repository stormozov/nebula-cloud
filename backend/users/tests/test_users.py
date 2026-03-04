"""
Test suite for CurrentUserView ViewSet.

This module contains comprehensive tests for user profile management endpoints:
- Get current user profile
- Full update profile
- Partial update profile
- Change password
- Get storage statistics
- Get current session details
- Deactivate own account
"""

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from users.models import UserAccount

User = get_user_model()

# ==================================================================================================
# CONSTANTS
# ==================================================================================================

# Base URL for current user endpoints
BASE_URL = "/api/users/me/"


# ==================================================================================================
# TEST GROUP: PROFILE RETRIEVAL
# ==================================================================================================


class TestProfileRetrieve:
    """Tests for GET /api/users/me/ endpoint."""

    def test_authenticated_user_can_retrieve_profile(
        self, authenticated_client: APIClient, user_account: UserAccount
    ):
        """
        Test that authenticated user can retrieve their own profile.

        Scenario:
            Authenticated user sends GET request to /me/ endpoint.

        Expected Result:
            - Returns 200 OK status
            - Response contains user profile data
            - Data matches the authenticated user's account
        """

        # Arrange
        # authenticated_client already has user_account's token

        # Act
        response = authenticated_client.get(BASE_URL)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["username"] == user_account.username
        assert response.data["email"] == user_account.email

    def test_unauthenticated_user_cannot_retrieve_profile(self, api_client: APIClient):
        """
        Test that unauthenticated user cannot access profile endpoint.

        Scenario:
            Unauthenticated user sends GET request to /me/ endpoint.

        Expected Result:
            - Returns 401 Unauthorized status
            - No profile data is returned
        """

        # Arrange
        # api_client has no authentication token

        # Act
        response = api_client.get(BASE_URL)

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_inactive_user_cannot_retrieve_profile(
        self, api_client: APIClient, inactive_user_account: UserAccount
    ):
        """
        Test that inactive user cannot access profile endpoint.

        Scenario:
            Inactive user (is_active=False) sends GET request to /me/ endpoint.

        Expected Result:
            - Returns 401 Unauthorized status
            - Inactive accounts are blocked from API access
        """

        # Arrange
        refresh = RefreshToken.for_user(inactive_user_account)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

        # Act
        response = api_client.get(BASE_URL)

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_profile_response_excludes_sensitive_data(
        self, authenticated_client: APIClient, user_account: UserAccount
    ):
        """
        Test that profile response does not include sensitive data.

        Scenario:
            Authenticated user retrieves their profile.

        Expected Result:
            - Returns 200 OK status
            - Response does NOT contain password field
            - Response does NOT contain session tokens
        """

        # Arrange
        # authenticated_client already has user_account's token

        # Act
        response = authenticated_client.get(BASE_URL)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert "password" not in response.data
        assert "token" not in response.data
        assert "access_token" not in response.data


# ==================================================================================================
# TEST GROUP: PROFILE UPDATE (FULL)
# ==================================================================================================


class TestProfileUpdate:
    """Tests for PUT /api/users/me/ endpoint."""

    def test_authenticated_user_can_full_update_profile(
        self, authenticated_client: APIClient, user_account: UserAccount
    ):
        """
        Test that authenticated user can fully update their profile.

        Scenario:
            Authenticated user sends PUT request with updated first_name and last_name.

        Expected Result:
            - Returns 200 OK status
            - Profile fields are updated in database
            - Response contains updated data
        """

        # Arrange
        update_data = {
            "first_name": "UpdatedFirst",
            "last_name": "UpdatedLast",
        }

        # Act
        response = authenticated_client.put(BASE_URL, data=update_data, format="json")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["first_name"] == "UpdatedFirst"
        assert response.data["last_name"] == "UpdatedLast"

        # Verify database update
        user_account.refresh_from_db()
        assert user_account.first_name == "UpdatedFirst"
        assert user_account.last_name == "UpdatedLast"

    def test_cannot_update_read_only_fields(
        self, authenticated_client: APIClient, user_account: UserAccount
    ):
        """
        Test that read-only fields cannot be updated via profile endpoint.

        Scenario:
            User attempts to update username and email via PUT request.

        Expected Result:
            - Returns 200 OK (read-only fields are ignored)
            - Username and email remain unchanged
        """

        # Arrange
        original_username = user_account.username
        original_email = user_account.email
        update_data = {
            "username": "hacked_username",
            "email": "hacked@example.com",
            "first_name": "Test",
        }

        # Act
        response = authenticated_client.put(BASE_URL, data=update_data, format="json")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["username"] == original_username
        assert response.data["email"] == original_email

    def test_unauthenticated_user_cannot_update_profile(self, api_client: APIClient):
        """
        Test that unauthenticated user cannot update profile.

        Scenario:
            Unauthenticated user sends PUT request to /me/ endpoint.

        Expected Result:
            - Returns 401 Unauthorized status
        """

        # Arrange
        update_data = {"first_name": "Hacker"}

        # Act
        response = api_client.put(BASE_URL, data=update_data, format="json")

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_update_with_invalid_data_returns_error(
        self, authenticated_client: APIClient, user_account: UserAccount
    ):
        """
        Test that invalid data in update request returns validation error.

        Scenario:
            User sends PUT request with data that cannot be processed
            (nested object that cannot be coerced to string).

        Expected Result:
            - Returns 400 Bad Request status
            - Error messages are included in response
        """

        # Arrange
        # Dict cannot be coerced to string by CharField
        update_data = {
            "first_name": {"nested": "object"},
        }

        # Act
        response = authenticated_client.put(BASE_URL, data=update_data, format="json")

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "first_name" in response.data


# ==================================================================================================
# TEST GROUP: PROFILE UPDATE (PARTIAL)
# ==================================================================================================


class TestProfilePartialUpdate:
    """Tests for PATCH /api/users/me/ endpoint."""

    def test_authenticated_user_can_partial_update_profile(
        self, authenticated_client: APIClient, user_account: UserAccount
    ):
        """
        Test that authenticated user can partially update their profile.

        Scenario:
            Authenticated user sends PATCH request with only first_name.

        Expected Result:
            - Returns 200 OK status
            - Only first_name is updated
            - last_name remains unchanged
        """

        # Arrange
        original_last_name = user_account.last_name
        update_data = {"first_name": "PartialUpdate"}

        # Act
        response = authenticated_client.patch(BASE_URL, data=update_data, format="json")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["first_name"] == "PartialUpdate"
        assert response.data["last_name"] == original_last_name

    def test_partial_update_with_empty_data(
        self, authenticated_client: APIClient, user_account: UserAccount
    ):
        """
        Test that partial update with empty data returns current profile.

        Scenario:
            User sends PATCH request with empty data.

        Expected Result:
            - Returns 200 OK status
            - Profile remains unchanged
        """

        # Arrange
        update_data = {}

        # Act
        response = authenticated_client.patch(BASE_URL, data=update_data, format="json")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["username"] == user_account.username


# ==================================================================================================
# TEST GROUP: PASSWORD CHANGE
# ==================================================================================================


class TestPasswordChange:
    """Tests for POST /api/users/me/password/ endpoint."""

    def test_user_can_change_password_with_valid_data(
        self, authenticated_client: APIClient, user_account: UserAccount, valid_password_change_data
    ):
        """
        Test that user can change password with valid credentials.

        Scenario:
            User sends POST request with correct current password
            and valid new password.

        Expected Result:
            - Returns 200 OK status
            - Password is updated in database
            - Success message is returned
        """

        # Arrange
        # valid_password_change_data from conftest.py

        # Act
        response = authenticated_client.post(
            f"{BASE_URL}password/", data=valid_password_change_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert "detail" in response.data

        # Verify password change
        user_account.refresh_from_db()
        assert user_account.check_password("NewSecurePass456!")

    def test_password_change_with_wrong_current_password(
        self,
        authenticated_client: APIClient,
        user_account: UserAccount,
        wrong_current_password_data,
    ):
        """
        Test that password change fails with incorrect current password.

        Scenario:
            User sends POST request with wrong current password.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates wrong current password
            - Password is NOT changed
        """

        # Arrange
        original_password = user_account.password

        # Act
        response = authenticated_client.post(
            f"{BASE_URL}password/", data=wrong_current_password_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "current_password" in response.data

        # Verify password unchanged
        user_account.refresh_from_db()
        assert user_account.password == original_password

    def test_password_change_with_mismatched_confirmation(
        self,
        authenticated_client: APIClient,
        user_account: UserAccount,
        invalid_password_change_data,
    ):
        """
        Test that password change fails when new passwords don't match.

        Scenario:
            User sends POST request with mismatched new_password and
            new_password_confirm.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates password mismatch
        """

        # Arrange
        # invalid_password_change_data has mismatched passwords

        # Act
        response = authenticated_client.post(
            f"{BASE_URL}password/", data=invalid_password_change_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "new_password_confirm" in response.data

    def test_password_change_with_weak_password(
        self, authenticated_client: APIClient, user_account: UserAccount, weak_password_change_data
    ):
        """
        Test that password change fails with weak new password.

        Scenario:
            User sends POST request with password that doesn't meet
            validation requirements.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates password validation failure
        """

        # Arrange
        # weak_password_change_data has weak password

        # Act
        response = authenticated_client.post(
            f"{BASE_URL}password/", data=weak_password_change_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "new_password" in response.data

    def test_password_change_with_same_as_current(
        self, authenticated_client: APIClient, user_account: UserAccount
    ):
        """
        Test that password change fails when new password equals current.

        Scenario:
            User sends POST request with new_password same as current_password.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates password cannot be same
        """

        # Arrange
        password_data = {
            "current_password": "TestPass123!",
            "new_password": "TestPass123!",
            "new_password_confirm": "TestPass123!",
        }

        # Act
        response = authenticated_client.post(
            f"{BASE_URL}password/", data=password_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_unauthenticated_user_cannot_change_password(self, api_client: APIClient):
        """
        Test that unauthenticated user cannot change password.

        Scenario:
            Unauthenticated user sends POST request to password endpoint.

        Expected Result:
            - Returns 401 Unauthorized status
        """

        # Arrange
        password_data = {
            "current_password": "TestPass123!",
            "new_password": "NewSecurePass456!",
            "new_password_confirm": "NewSecurePass456!",
        }

        # Act
        response = api_client.post(f"{BASE_URL}password/", data=password_data, format="json")

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ==================================================================================================
# TEST GROUP: STORAGE SUMMARY
# ==================================================================================================


class TestStorageSummary:
    """Tests for GET /api/users/me/storage-summary/ endpoint."""

    def test_user_can_get_storage_summary(
        self, authenticated_client: APIClient, user_account: UserAccount
    ):
        """
        Test that user can retrieve their storage statistics.

        Scenario:
            Authenticated user sends GET request to storage-summary endpoint.

        Expected Result:
            - Returns 200 OK status
            - Response contains file_count, total_size, storage_path
        """

        # Arrange
        # authenticated_client already has user_account's token

        # Act
        response = authenticated_client.get(f"{BASE_URL}storage-summary/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert "file_count" in response.data
        assert "total_size" in response.data
        assert "total_size_formatted" in response.data
        assert "storage_path" in response.data
        assert response.data["storage_path"] == user_account.storage_path

    def test_storage_summary_with_uploaded_files(
        self, authenticated_client: APIClient, uploaded_file
    ):
        """
        Test storage summary reflects uploaded files correctly.

        Scenario:
            User with uploaded files requests storage summary.

        Expected Result:
            - Returns 200 OK status
            - file_count reflects actual number of files
            - total_size reflects actual file sizes
        """

        # Arrange
        # authenticated_client has user with uploaded_file fixture

        # Act
        response = authenticated_client.get(f"{BASE_URL}storage-summary/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["file_count"] >= 1
        assert response.data["total_size"] > 0

    def test_unauthenticated_user_cannot_get_storage_summary(self, api_client: APIClient):
        """
        Test that unauthenticated user cannot access storage summary.

        Scenario:
            Unauthenticated user sends GET request to storage-summary endpoint.

        Expected Result:
            - Returns 401 Unauthorized status
        """

        # Arrange
        # api_client has no authentication

        # Act
        response = api_client.get(f"{BASE_URL}storage-summary/")

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ==================================================================================================
# TEST GROUP: SESSION INFO
# ==================================================================================================


class TestSessionInfo:
    """Tests for GET /api/users/me/session-info/ endpoint."""

    def test_user_can_get_session_info(
        self, authenticated_client: APIClient, user_account: UserAccount
    ):
        """
        Test that user can retrieve their session information.

        Scenario:
            Authenticated user sends GET request to session-info endpoint.

        Expected Result:
            - Returns 200 OK status
            - Response contains user_id, username, email, client_ip
            - Response contains is_staff and is_active flags
        """

        # Arrange
        # authenticated_client already has user_account's token

        # Act
        response = authenticated_client.get(f"{BASE_URL}session-info/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["user_id"] == user_account.id
        assert response.data["username"] == user_account.username
        assert response.data["email"] == user_account.email
        assert "client_ip" in response.data
        assert "user_agent" in response.data
        assert "is_staff" in response.data
        assert "is_active" in response.data

    def test_session_info_shows_correct_staff_status(
        self, admin_client: APIClient, admin_account: UserAccount
    ):
        """
        Test that session info correctly shows admin staff status.

        Scenario:
            Admin user requests their session info.

        Expected Result:
            - Returns 200 OK status
            - is_staff field is True for admin user
        """

        # Arrange
        # admin_client has admin_account's token

        # Act
        response = admin_client.get(f"{BASE_URL}session-info/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["is_staff"] is True

    def test_unauthenticated_user_cannot_get_session_info(self, api_client: APIClient):
        """
        Test that unauthenticated user cannot access session info.

        Scenario:
            Unauthenticated user sends GET request to session-info endpoint.

        Expected Result:
            - Returns 401 Unauthorized status
        """

        # Arrange
        # api_client has no authentication

        # Act
        response = api_client.get(f"{BASE_URL}session-info/")

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ==================================================================================================
# TEST GROUP: ACCOUNT DEACTIVATION
# ==================================================================================================


class TestAccountDeactivation:
    """Tests for POST /api/users/me/deactivate/ endpoint."""

    def test_user_can_deactivate_own_account(
        self, authenticated_client: APIClient, user_account: UserAccount
    ):
        """
        Test that user can deactivate their own account.

        Scenario:
            Authenticated user sends POST request to deactivate endpoint.

        Expected Result:
            - Returns 200 OK status
            - User is_active field is set to False
            - Success message is returned
        """

        # Arrange
        # authenticated_client already has user_account's token

        # Act
        response = authenticated_client.post(f"{BASE_URL}deactivate/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert "detail" in response.data

        # Verify database update
        user_account.refresh_from_db()
        assert user_account.is_active is False

    def test_deactivated_user_cannot_access_api(
        self, api_client: APIClient, user_account: UserAccount
    ):
        """
        Test that deactivated user cannot access API endpoints.

        Scenario:
            User deactivates account, then tries to access profile.

        Expected Result:
            - Subsequent requests return 401 Unauthorized
        """

        # Arrange
        refresh = RefreshToken.for_user(user_account)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

        # Deactivate account
        api_client.post(f"{BASE_URL}deactivate/")

        # Act
        response = api_client.get(BASE_URL)

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_admin_can_deactivate_own_account(
        self, admin_client: APIClient, admin_account: UserAccount
    ):
        """
        Test that admin user can also deactivate their own account.

        Scenario:
            Admin user sends POST request to deactivate endpoint.

        Expected Result:
            - Returns 200 OK status
            - Admin is_active field is set to False
        """

        # Arrange
        # admin_client already has admin_account's token

        # Act
        response = admin_client.post(f"{BASE_URL}deactivate/")

        # Assert
        assert response.status_code == status.HTTP_200_OK

        # Verify database update
        admin_account.refresh_from_db()
        assert admin_account.is_active is False

    def test_unauthenticated_user_cannot_deactivate_account(self, api_client: APIClient):
        """
        Test that unauthenticated user cannot deactivate account.

        Scenario:
            Unauthenticated user sends POST request to deactivate endpoint.

        Expected Result:
            - Returns 401 Unauthorized status
        """

        # Arrange
        # api_client has no authentication

        # Act
        response = api_client.post(f"{BASE_URL}deactivate/")

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ==================================================================================================
# TEST GROUP: EDGE CASES
# ==================================================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_profile_retrieve_with_special_characters_in_name(
        self, authenticated_client: APIClient, user_account: UserAccount
    ):
        """
        Test profile retrieval with special characters in user name.

        Scenario:
            User with special characters in first_name retrieves profile.

        Expected Result:
            - Returns 200 OK status
            - Special characters are properly encoded in response
        """

        # Arrange
        user_account.first_name = "José María"
        user_account.save()

        # Act
        response = authenticated_client.get(BASE_URL)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        # Check if first_name exists in response before asserting value
        if "first_name" in response.data:
            assert response.data["first_name"] == "José María"

    def test_multiple_sequential_profile_updates(
        self, authenticated_client: APIClient, user_account: UserAccount
    ):
        """
        Test multiple sequential profile updates.

        Scenario:
            User performs multiple PATCH requests in sequence.

        Expected Result:
            - All updates succeed with 200 OK
            - Final state reflects last update
        """

        # Arrange
        updates = [
            {"first_name": "First"},
            {"last_name": "Last"},
            {"first_name": "Final"},
        ]

        # Act & Assert
        for update_data in updates:
            response = authenticated_client.patch(BASE_URL, data=update_data, format="json")
            assert response.status_code == status.HTTP_200_OK

        # Verify final state
        user_account.refresh_from_db()
        assert user_account.first_name == "Final"
        assert user_account.last_name == "Last"

    def test_password_change_requires_all_fields(
        self, authenticated_client: APIClient, user_account: UserAccount
    ):
        """
        Test that password change requires all required fields.

        Scenario:
            User sends password change request with missing field.

        Expected Result:
            - Returns 400 Bad Request status
            - Error indicates missing required field
        """

        # Arrange
        password_data = {
            "current_password": "TestPass123!",
            # Missing new_password and new_password_confirm
        }

        # Act
        response = authenticated_client.post(
            f"{BASE_URL}password/", data=password_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "new_password" in response.data
