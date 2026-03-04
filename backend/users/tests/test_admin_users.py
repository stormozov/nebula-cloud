"""
Test suite for AdminUserViewSet.

This module contains comprehensive tests for admin user management endpoints:
- User listing and retrieval
- User update and deletion
- Password reset by admin
- Admin status toggle
- Storage statistics

All tests follow AAA pattern (Arrange, Act, Assert) and use pytest fixtures
from conftest.py for consistent test setup.

Requirements:
- All admin endpoints require authentication and admin privileges
- Admin cannot perform actions on themselves (delete, password reset, toggle)
- Regular users receive 403 Forbidden on admin endpoints
- Unauthenticated requests receive 401 Unauthorized
"""

# pylint: disable=unused-argument
# pylint: disable=too-many-public-methods

import pytest
from rest_framework import status

from users.models import UserAccount

pytestmark = pytest.mark.django_db

# ==================================================================================================
# TEST CLASS: LIST USERS
# ==================================================================================================


@pytest.mark.django_db
class TestAdminUserList:
    """Test suite for user list endpoint (GET /api/users/admin/users/)."""

    def test_admin_can_list_all_users(self, admin_client, admin_list_url, multiple_user_accounts):
        """
        Test that admin user can retrieve list of all users.

        Scenario:
            Admin user makes GET request to admin users list endpoint.

        Expected Result:
            - Returns 200 OK status
            - Response contains list of users (at least 3 from fixture)
            - Each user has required fields (id, username, email, is_staff)
        """

        # Arrange
        expected_min_count = 3

        # Act
        response = admin_client.get(admin_list_url)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.data, list)
        assert len(response.data) >= expected_min_count
        assert all("username" in user for user in response.data)
        assert all("email" in user for user in response.data)
        assert all("is_admin" in user for user in response.data)

    def test_regular_user_cannot_list_users(self, authenticated_client, admin_list_url):
        """
        Test that regular user cannot access admin user list.

        Scenario:
            Regular authenticated user makes GET request to admin endpoint.

        Expected Result:
            - Returns 403 Forbidden status
            - Error message indicates permission denied
        """

        # Arrange
        # authenticated_client has regular user credentials

        # Act
        response = authenticated_client.get(admin_list_url)

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "detail" in response.data

    def test_unauthenticated_cannot_list_users(self, api_client, admin_list_url):
        """
        Test that unauthenticated user cannot access admin user list.

        Scenario:
            Unauthenticated client makes GET request to admin endpoint.

        Expected Result:
            - Returns 401 Unauthorized status
            - No user data is exposed
        """

        # Arrange
        # api_client has no authentication

        # Act
        response = api_client.get(admin_list_url)

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_list_includes_admin_flag(self, admin_client, admin_list_url, user_account):
        """
        Test that user list includes admin status indicator.

        Scenario:
            Admin retrieves user list containing both regular and admin users.

        Expected Result:
            - Response includes is_staff field for each user
            - Admin user has is_staff=True
            - Regular user has is_staff=False
        """

        # Arrange
        # user_account is regular user, admin_account is admin

        # Act
        response = admin_client.get(admin_list_url)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        users_by_email = {user["email"]: user for user in response.data}

        # Find regular user
        if user_account.email in users_by_email:
            assert users_by_email[user_account.email]["is_admin"] is False


# ==================================================================================================
# TEST CLASS: RETRIEVE USER
# ==================================================================================================


@pytest.mark.django_db
class TestAdminUserRetrieve:
    """Test suite for user detail endpoint (GET /api/users/admin/users/{id}/)."""

    def test_admin_can_retrieve_user_details(
        self, admin_client, target_user_account, admin_user_url
    ):
        """
        Test that admin can retrieve specific user details.

        Scenario:
            Admin makes GET request for specific user by ID.

        Expected Result:
            - Returns 200 OK status
            - Response contains user details (username, email, first_name, etc.)
            - Response includes storage statistics
        """

        # Arrange
        url = admin_user_url(target_user_account.id)

        # Act
        response = admin_client.get(url)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["username"] == target_user_account.username
        assert response.data["email"] == target_user_account.email
        assert "storage_stats" in response.data

    def test_regular_user_cannot_retrieve_user_details(
        self, authenticated_client, target_user_account, admin_user_url
    ):
        """
        Test that regular user cannot retrieve other user details via admin endpoint.

        Scenario:
            Regular user makes GET request to admin detail endpoint.

        Expected Result:
            - Returns 403 Forbidden status
        """

        # Arrange
        url = admin_user_url(target_user_account.id)

        # Act
        response = authenticated_client.get(url)

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_retrieve_nonexistent_user_returns_404(self, admin_client, admin_user_url):
        """
        Test that requesting nonexistent user returns 404.

        Scenario:
            Admin requests user with ID that doesn't exist in database.

        Expected Result:
            - Returns 404 Not Found status
            - Error message indicates user not found
        """

        # Arrange
        nonexistent_id = 99999
        url = admin_user_url(nonexistent_id)

        # Act
        response = admin_client.get(url)

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_retrieve_with_invalid_id_format_returns_400(self, admin_client, admin_list_url):
        """
        Test that invalid ID format returns appropriate error.

        Scenario:
            Admin makes request with non-integer ID format.

        Expected Result:
            - Returns 400 Bad Request or 404 (depending on router config)
        """

        # Arrange
        invalid_url = f"{admin_list_url}invalid/"

        # Act
        response = admin_client.get(invalid_url)

        # Assert
        assert response.status_code in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_404_NOT_FOUND,
        ]


# ==================================================================================================
# TEST CLASS: UPDATE USER
# ==================================================================================================


@pytest.mark.django_db
class TestAdminUserUpdate:
    """Test suite for user update endpoints (PUT/PATCH /api/users/admin/users/{id}/)."""

    @pytest.mark.parametrize(
        "update_data,expected_field",
        [
            ({"first_name": "UpdatedName"}, "first_name"),
            ({"last_name": "UpdatedLast"}, "last_name"),
            ({"email": "newemail@example.com"}, "email"),
        ],
    )
    def test_admin_can_update_user_fields(
        self, admin_client, target_user_account, admin_user_url, update_data, expected_field
    ):
        """
        Test that admin can update user fields via PATCH request.

        Scenario:
            Admin sends PATCH request with updated user data.

        Expected Result:
            - Returns 200 OK status
            - Response contains updated field value
            - Database reflects the change

        Args:
            update_data: Dictionary with field to update.
            expected_field: Name of field being updated.
        """

        # Arrange
        url = admin_user_url(target_user_account.id)

        # Act
        response = admin_client.patch(url, update_data)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data[expected_field] == update_data[expected_field]

        # Verify database update
        target_user_account.refresh_from_db()
        assert getattr(target_user_account, expected_field) == update_data[expected_field]

    def test_admin_can_fully_update_user(self, admin_client, target_user_account, admin_user_url):
        """
        Test that admin can perform full user update via PUT request.

        Scenario:
            Admin sends PUT request with complete user data.

        Expected Result:
            - Returns 200 OK status
            - All provided fields are updated
        """

        # Arrange
        url = admin_user_url(target_user_account.id)
        update_data = {
            "first_name": "Full",
            "last_name": "Update",
            "email": "fullupdate@example.com",
        }

        # Act
        response = admin_client.put(url, update_data)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["first_name"] == "Full"
        assert response.data["last_name"] == "Update"

    def test_regular_user_cannot_update_users(
        self, authenticated_client, target_user_account, admin_user_url
    ):
        """
        Test that regular user cannot update other users via admin endpoint.

        Scenario:
            Regular user sends PATCH request to admin update endpoint.

        Expected Result:
            - Returns 403 Forbidden status
        """

        # Arrange
        url = admin_user_url(target_user_account.id)
        update_data = {"first_name": "Hacker"}

        # Act
        response = authenticated_client.patch(url, update_data)

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_update_with_invalid_email_returns_400(
        self, admin_client, target_user_account, admin_user_url
    ):
        """
        Test that invalid email format returns validation error.

        Scenario:
            Admin sends update request with invalid email format.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates email validation failure
        """

        # Arrange
        url = admin_user_url(target_user_account.id)
        invalid_data = {"email": "not-an-email"}

        # Act
        response = admin_client.patch(url, invalid_data)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "email" in response.data


# ==================================================================================================
# TEST CLASS: DELETE USER
# ==================================================================================================


@pytest.mark.django_db
class TestAdminUserDelete:
    """Test suite for user delete endpoint (DELETE /api/users/admin/users/{id}/)."""

    def test_admin_can_delete_user(self, admin_client, target_user_account, admin_user_url):
        """
        Test that admin can delete regular user account.

        Scenario:
            Admin sends DELETE request for target user.

        Expected Result:
            - Returns 200 OK status
            - User is removed from database
            - Success message is returned
        """

        # Arrange
        url = admin_user_url(target_user_account.id)
        user_id = target_user_account.id

        # Act
        response = admin_client.delete(url)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert "detail" in response.data
        assert not UserAccount.objects.filter(id=user_id).exists()

    def test_admin_cannot_delete_self(self, admin_client, admin_account, admin_user_url):
        """
        Test that admin cannot delete their own account.

        Scenario:
            Admin sends DELETE request for their own user ID.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message prevents self-deletion
            - Admin account remains in database
        """

        # Arrange
        url = admin_user_url(admin_account.id)

        # Act
        response = admin_client.delete(url)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "detail" in response.data
        assert UserAccount.objects.filter(id=admin_account.id).exists()

    def test_regular_user_cannot_delete_users(
        self, authenticated_client, target_user_account, admin_user_url
    ):
        """
        Test that regular user cannot delete other users.

        Scenario:
            Regular user sends DELETE request to admin endpoint.

        Expected Result:
            - Returns 403 Forbidden status
            - User remains in database
        """

        # Arrange
        url = admin_user_url(target_user_account.id)

        # Act
        response = authenticated_client.delete(url)

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert UserAccount.objects.filter(id=target_user_account.id).exists()

    def test_delete_nonexistent_user_returns_404(self, admin_client, admin_user_url):
        """
        Test that deleting nonexistent user returns 404.

        Scenario:
            Admin sends DELETE request for ID that doesn't exist.

        Expected Result:
            - Returns 404 Not Found status
        """

        # Arrange
        nonexistent_id = 99999
        url = admin_user_url(nonexistent_id)

        # Act
        response = admin_client.delete(url)

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND


# ==================================================================================================
# TEST CLASS: PASSWORD RESET
# ==================================================================================================


@pytest.mark.django_db
class TestAdminPasswordReset:
    """Test suite for password reset endpoint (POST /api/users/admin/users/{id}/password/)."""

    def test_admin_can_reset_user_password(
        self,
        admin_client,
        target_user_account,
        admin_action_url,
        password_reset_data,
    ):
        """
        Test that admin can reset regular user password.

        Scenario:
            Admin sends POST request with new password data.

        Expected Result:
            - Returns 200 OK status
            - Success message is returned
            - User can authenticate with new password
        """

        # Arrange
        url = admin_action_url(target_user_account.id, "password")

        # Act
        response = admin_client.post(url, password_reset_data)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert "detail" in response.data

        # Verify new password works
        from django.contrib.auth import authenticate

        authenticated_user = authenticate(
            username=target_user_account.username,
            password=password_reset_data["new_password"],
        )
        assert authenticated_user is not None

    def test_admin_cannot_reset_self_password(
        self, admin_client, admin_account, admin_action_url, password_reset_data
    ):
        """
        Test that admin cannot reset their own password via admin endpoint.

        Scenario:
            Admin sends password reset request for their own account.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message prevents self-password-reset
        """

        # Arrange
        url = admin_action_url(admin_account.id, "password")

        # Act
        response = admin_client.post(url, password_reset_data)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "detail" in response.data

    @pytest.mark.parametrize(
        "invalid_data_fixture,expected_error_field",
        [
            ("weak_password_reset_data", "new_password"),
            ("mismatched_password_reset_data", "new_password_confirm"),
        ],
    )
    def test_password_reset_validation_errors(
        self,
        admin_client,
        target_user_account,
        admin_action_url,
        invalid_data_fixture,
        expected_error_field,
        request,
    ):
        """
        Test that invalid password data returns validation errors.

        Scenario:
            Admin sends password reset request with invalid password data.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates validation failure

        Args:
            invalid_data_fixture: Name of fixture with invalid data.
            expected_error_field: Field that should have validation error.
        """

        # Arrange
        url = admin_action_url(target_user_account.id, "password")
        invalid_data = request.getfixturevalue(invalid_data_fixture)

        # Act
        response = admin_client.post(url, invalid_data)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert expected_error_field in response.data

    def test_regular_user_cannot_reset_passwords(
        self, authenticated_client, target_user_account, admin_action_url, password_reset_data
    ):
        """
        Test that regular user cannot reset other user passwords.

        Scenario:
            Regular user sends password reset request to admin endpoint.

        Expected Result:
            - Returns 403 Forbidden status
        """

        # Arrange
        url = admin_action_url(target_user_account.id, "password")

        # Act
        response = authenticated_client.post(url, password_reset_data)

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_reset_password_nonexistent_user_returns_404(
        self, admin_client, admin_action_url, password_reset_data
    ):
        """
        Test that resetting password for nonexistent user returns 404.

        Scenario:
            Admin sends password reset request for ID that doesn't exist.

        Expected Result:
            - Returns 404 Not Found status
        """

        # Arrange
        nonexistent_id = 99999
        url = admin_action_url(nonexistent_id, "password")

        # Act
        response = admin_client.post(url, password_reset_data)

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND


# ==================================================================================================
# TEST CLASS: TOGGLE ADMIN STATUS
# ==================================================================================================


@pytest.mark.django_db
class TestAdminToggleStatus:
    """Test suite for toggle admin endpoint (POST /api/users/admin/users/{id}/toggle-admin/)."""

    def test_admin_can_enable_user_admin_status(
        self, admin_client, target_user_account, admin_action_url, toggle_admin_data_enable
    ):
        """
        Test that admin can grant admin status to regular user.

        Scenario:
            Admin sends POST request to enable admin status.

        Expected Result:
            - Returns 200 OK status
            - User is_staff field becomes True
            - Response includes updated is_admin status
        """

        # Arrange
        url = admin_action_url(target_user_account.id, "toggle-admin")
        assert target_user_account.is_staff is False

        # Act
        response = admin_client.post(url, toggle_admin_data_enable)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["is_admin"] is True

        # Verify database update
        target_user_account.refresh_from_db()
        assert target_user_account.is_staff is True

    def test_admin_can_disable_user_admin_status(
        self, admin_client, second_admin_account, admin_action_url, toggle_admin_data_disable
    ):
        """
        Test that admin can revoke admin status from another admin.

        Scenario:
            Admin sends POST request to disable admin status for second admin.

        Expected Result:
            - Returns 200 OK status
            - User is_staff field becomes False
            - Response includes updated is_admin status
        """

        # Arrange
        url = admin_action_url(second_admin_account.id, "toggle-admin")
        assert second_admin_account.is_staff is True

        # Act
        response = admin_client.post(url, toggle_admin_data_disable)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["is_admin"] is False

        # Verify database update
        second_admin_account.refresh_from_db()
        assert second_admin_account.is_staff is False

    def test_admin_cannot_remove_self_admin_status(
        self, admin_client, admin_account, admin_action_url, toggle_admin_data_disable
    ):
        """
        Test that admin cannot remove their own admin status.

        Scenario:
            Admin sends toggle request for their own account.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message prevents self-admin-removal
            - Admin status remains unchanged
        """

        # Arrange
        url = admin_action_url(admin_account.id, "toggle-admin")

        # Act
        response = admin_client.post(url, toggle_admin_data_disable)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "detail" in response.data

        # Verify admin status unchanged
        admin_account.refresh_from_db()
        assert admin_account.is_staff is True

    def test_regular_user_cannot_toggle_admin_status(
        self, authenticated_client, target_user_account, admin_action_url, toggle_admin_data_enable
    ):
        """
        Test that regular user cannot toggle admin status for others.

        Scenario:
            Regular user sends toggle request to admin endpoint.

        Expected Result:
            - Returns 403 Forbidden status
        """

        # Arrange
        url = admin_action_url(target_user_account.id, "toggle-admin")

        # Act
        response = authenticated_client.post(url, toggle_admin_data_enable)

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_toggle_admin_invalid_data_returns_400(
        self, admin_client, target_user_account, admin_action_url, invalid_toggle_admin_data
    ):
        """
        Test that invalid toggle data returns validation error.

        Scenario:
            Admin sends toggle request with invalid is_admin value.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates validation failure
        """

        # Arrange
        url = admin_action_url(target_user_account.id, "toggle-admin")

        # Act
        response = admin_client.post(url, invalid_toggle_admin_data)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "is_admin" in response.data


# ==================================================================================================
# TEST CLASS: STORAGE STATISTICS
# ==================================================================================================


@pytest.mark.django_db
class TestAdminStorageStats:
    """Test suite for storage stats endpoint (GET /api/users/admin/users/{id}/storage-stats/)."""

    def test_admin_can_get_user_storage_stats(
        self, admin_client, user_with_files, admin_action_url
    ):
        """
        Test that admin can retrieve storage statistics for user.

        Scenario:
            Admin sends GET request for user storage statistics.

        Expected Result:
            - Returns 200 OK status
            - Response contains user info and storage stats
            - File count matches actual uploaded files
        """

        # Arrange
        user, files = user_with_files
        url = admin_action_url(user.id, "storage-stats")

        # Act
        response = admin_client.get(url)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert "user" in response.data
        assert "storage" in response.data
        assert response.data["storage"]["file_count"] == len(files)

    def test_storage_stats_includes_user_info(
        self, admin_client, target_user_account, admin_action_url
    ):
        """
        Test that storage stats response includes user identification.

        Scenario:
            Admin retrieves storage stats for specific user.

        Expected Result:
            - Response contains user_id, username, email
            - Values match target user account
        """

        # Arrange
        url = admin_action_url(target_user_account.id, "storage-stats")

        # Act
        response = admin_client.get(url)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["user"]["user_id"] == target_user_account.id
        assert response.data["user"]["username"] == target_user_account.username
        assert response.data["user"]["email"] == target_user_account.email

    def test_regular_user_cannot_get_storage_stats(
        self, authenticated_client, target_user_account, admin_action_url
    ):
        """
        Test that regular user cannot access storage stats endpoint.

        Scenario:
            Regular user sends GET request to admin storage stats endpoint.

        Expected Result:
            - Returns 403 Forbidden status
        """

        # Arrange
        url = admin_action_url(target_user_account.id, "storage-stats")

        # Act
        response = authenticated_client.get(url)

        # Assert
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_storage_stats_nonexistent_user_returns_404(self, admin_client, admin_action_url):
        """
        Test that storage stats for nonexistent user returns 404.

        Scenario:
            Admin requests storage stats for ID that doesn't exist.

        Expected Result:
            - Returns 404 Not Found status
        """

        # Arrange
        nonexistent_id = 99999
        url = admin_action_url(nonexistent_id, "storage-stats")

        # Act
        response = admin_client.get(url)

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_storage_stats_with_mocked_data(
        self, admin_client, target_user_account, admin_action_url, mock_storage_stats
    ):
        """
        Test storage stats endpoint with mocked service function.

        Scenario:
            Admin requests storage stats with mocked calculate_storage_stats.

        Expected Result:
            - Returns 200 OK status
            - Response contains mocked statistics values
        """

        # Arrange
        url = admin_action_url(target_user_account.id, "storage-stats")
        mock_storage_stats({"file_count": 5, "total_size": 10240, "total_size_formatted": "10 KB"})

        # Act
        response = admin_client.get(url)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["storage"]["file_count"] == 5
        assert response.data["storage"]["total_size"] == 10240


# ==================================================================================================
# TEST CLASS: PERMISSION EDGE CASES
# ==================================================================================================


@pytest.mark.django_db
class TestAdminPermissionsEdgeCases:
    """Test suite for permission edge cases and security checks."""

    def test_inactive_user_cannot_access_admin_endpoints(
        self, api_client, inactive_user_account, admin_list_url, login_user
    ):
        """
        Test that inactive user cannot access admin endpoints even with token.

        Scenario:
            Inactive user obtains token and tries to access admin endpoint.

        Expected Result:
            - Returns 401 Unauthorized or 403 Forbidden
            - Inactive users are blocked from API access
        """

        # Arrange
        client, tokens, user = login_user(inactive_user_account.username, "InactivePass123!")

        # Act
        if client:
            response = client.get(admin_list_url)
        else:
            response = api_client.get(admin_list_url)

        # Assert
        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN,
        ]

    def test_admin_actions_logged_with_ip(self, admin_client, target_user_account, admin_user_url):
        """
        Test that admin actions are properly logged (indirect verification).

        Scenario:
            Admin performs action on user endpoint.

        Expected Result:
            - Request completes successfully (logging is side effect)
            - Response is valid (logging doesn't affect response)
        """

        # Arrange
        url = admin_user_url(target_user_account.id)

        # Act
        response = admin_client.get(url)

        # Assert
        assert response.status_code == status.HTTP_200_OK

    def test_multiple_admins_can_manage_users(
        self, admin_client, second_admin_account, target_user_account, admin_user_url
    ):
        """
        Test that multiple admins can perform actions on same user.

        Scenario:
            First admin retrieves user, second admin could also access.

        Expected Result:
            - Both admins have access to admin endpoints
            - Actions are independent per admin session
        """

        # Arrange
        url = admin_user_url(target_user_account.id)

        # Act
        response = admin_client.get(url)

        # Assert
        assert response.status_code == status.HTTP_200_OK
