"""
Tests for admin user management functionality.

This module tests the admin endpoints:
- GET /api/admin/users/
- GET/PUT/DELETE /api/admin/users/{id}/
- POST /api/admin/users/{id}/password/
- POST /api/admin/users/{id}/toggle-admin/
- GET /api/admin/users/{id}/storage-stats/
"""

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status

User = get_user_model()


class TestAdminUserListView:
    """Test cases for AdminUserListView endpoint."""

    def test_admin_can_list_users(self, admin_client, user_account):
        """Test that admin can retrieve list of all users."""

        url = reverse("users:admin_user_list")

        response = admin_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        # Response is paginated: check 'results' key
        assert "results" in response.data
        assert isinstance(response.data["results"], list)
        assert len(response.data["results"]) >= 2  # admin + user_account
        assert any(u["username"] == user_account.username for u in response.data["results"])

    def test_regular_user_cannot_list_users(self, authenticated_client):
        """Test that regular user cannot access admin user list."""

        url = reverse("users:admin_user_list")

        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_unauthenticated_cannot_list_users(self, api_client):
        """Test that unauthenticated user cannot access admin user list."""

        url = reverse("users:admin_user_list")

        response = api_client.get(url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_admin_list_includes_storage_stats(self, admin_client, uploaded_file):
        """Test that admin user list includes storage statistics."""

        url = reverse("users:admin_user_list")

        response = admin_client.get(url)

        assert response.status_code == status.HTTP_200_OK

        # Find user in paginated results
        user_data = next(
            (u for u in response.data["results"] if u["id"] == uploaded_file.owner.id), None
        )
        assert user_data is not None, "User not found in results"
        assert "storage_stats" in user_data
        assert "file_count" in user_data["storage_stats"]
        assert "total_size" in user_data["storage_stats"]


class TestAdminUserDetailView:
    """Test cases for AdminUserDetailView endpoint."""

    def test_admin_can_get_user_details(self, admin_client, user_account):
        """Test that admin can retrieve specific user details."""

        url = reverse("users:admin_user_detail", kwargs={"pk": user_account.id})

        response = admin_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["username"] == user_account.username
        assert response.data["email"] == user_account.email
        assert "storage_stats" in response.data

    def test_admin_can_update_user(self, admin_client, user_account):
        """Test that admin can update user data."""

        url = reverse("users:admin_user_detail", kwargs={"pk": user_account.id})
        data = {
            "first_name": "Updated",
            "last_name": "Name",
            "email": "updated@example.com",
        }

        response = admin_client.put(url, data)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["first_name"] == "Updated"
        assert response.data["last_name"] == "Name"

        # Verify in database
        user_account.refresh_from_db()
        assert user_account.first_name == "Updated"

    def test_admin_can_delete_user(self, admin_client, user_account):
        """Test that admin can delete user."""

        url = reverse("users:admin_user_detail", kwargs={"pk": user_account.id})
        user_id = user_account.id

        response = admin_client.delete(url)

        assert response.status_code == status.HTTP_200_OK
        assert not User.objects.filter(id=user_id).exists()

    def test_admin_cannot_delete_self(self, admin_client):
        """Test that admin cannot delete their own account."""

        url = reverse("users:admin_user_detail", kwargs={"pk": admin_client.user.id})

        response = admin_client.delete(url)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "нельзя удалить собственную" in response.data["detail"].lower()

    def test_regular_user_cannot_access_admin_detail(self, authenticated_client, user_account):
        """Test that regular user cannot access admin user detail."""
        url = reverse("users:admin_user_detail", kwargs={"pk": user_account.id})
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestAdminPasswordResetView:
    """Test cases for AdminPasswordResetView endpoint."""

    def test_admin_can_reset_user_password(self, admin_client, user_account):
        """Test that admin can reset another user's password."""

        url = reverse("users:admin_password_reset", kwargs={"pk": user_account.id})
        data = {
            "new_password": "NewResetPass123!",
            "new_password_confirm": "NewResetPass123!",
        }

        response = admin_client.post(url, data)

        assert response.status_code == status.HTTP_200_OK

        # Verify new password works
        login_response = admin_client.post(
            reverse("users:login"),
            {"username": user_account.username, "password": "NewResetPass123!"},
        )
        assert login_response.status_code == status.HTTP_200_OK

    def test_admin_cannot_reset_self_password(self, admin_client):
        """Test that admin cannot use this endpoint for own password."""

        url = reverse("users:admin_password_reset", kwargs={"pk": admin_client.user.id})
        data = {
            "new_password": "NewPass123!",
            "new_password_confirm": "NewPass123!",
        }

        response = admin_client.post(url, data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "для себя" in response.data["detail"]

    def test_regular_user_cannot_reset_password(self, authenticated_client, user_account):
        """Test that regular user cannot reset passwords."""

        url = reverse("users:admin_password_reset", kwargs={"pk": user_account.id})
        data = {
            "new_password": "NewPass123!",
            "new_password_confirm": "NewPass123!",
        }

        response = authenticated_client.post(url, data)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_password_reset_validates_strength(self, admin_client, user_account):
        """Test that admin password reset validates password strength."""

        url = reverse("users:admin_password_reset", kwargs={"pk": user_account.id})
        data = {
            "new_password": "weak",
            "new_password_confirm": "weak",
        }

        response = admin_client.post(url, data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "new_password" in response.data


class TestAdminToggleAdminView:
    """Test cases for AdminToggleAdminView endpoint."""

    def test_admin_can_grant_admin_status(self, admin_client, user_account):
        """Test that admin can grant admin status to another user."""

        url = reverse("users:admin_toggle_admin", kwargs={"pk": user_account.id})
        data = {"is_admin": True}

        response = admin_client.post(url, data)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["is_admin"] is True

        # Verify in database
        user_account.refresh_from_db()
        assert user_account.is_staff is True

    def test_admin_can_revoke_admin_status(self, admin_client, create_test_user):
        """Test that admin can revoke admin status from another admin."""

        # Create another admin user (not the one making the request)
        other_admin = create_test_user(
            username="other_admin",
            email="other_admin@example.com",
            is_staff=True,
        )

        url = reverse("users:admin_toggle_admin", kwargs={"pk": other_admin.id})
        data = {"is_admin": False}

        response = admin_client.post(url, data)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["is_admin"] is False

        # Verify in database
        other_admin.refresh_from_db()
        assert other_admin.is_staff is False

    def test_admin_cannot_toggle_self_status(self, admin_client):
        """Test that admin cannot change their own admin status."""

        url = reverse("users:admin_toggle_admin", kwargs={"pk": admin_client.user.id})
        data = {"is_admin": False}

        response = admin_client.post(url, data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "собственный статус" in response.data["detail"]

    def test_regular_user_cannot_toggle_admin(self, authenticated_client, user_account):
        """Test that regular user cannot toggle admin status."""

        url = reverse("users:admin_toggle_admin", kwargs={"pk": user_account.id})
        data = {"is_admin": True}

        response = authenticated_client.post(url, data)

        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestAdminUserStorageStatsView:
    """Test cases for AdminUserStorageStatsView endpoint."""

    def test_admin_can_get_storage_stats(self, admin_client, uploaded_file):
        """Test that admin can get user storage statistics."""

        url = reverse("users:admin_storage_stats", kwargs={"pk": uploaded_file.owner.id})

        response = admin_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["file_count"] >= 1
        assert "total_size" in response.data
        assert "storage_path" in response.data

    def test_regular_user_cannot_get_storage_stats(self, authenticated_client, user_account):
        """Test that regular user cannot access storage stats endpoint."""
        url = reverse("users:admin_storage_stats", kwargs={"pk": user_account.id})
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_storage_stats_nonexistent_user(self, admin_client):
        """Test storage stats for non-existent user returns 404."""
        url = reverse("users:admin_storage_stats", kwargs={"pk": 99999})
        response = admin_client.get(url)
        assert response.status_code == status.HTTP_404_NOT_FOUND
