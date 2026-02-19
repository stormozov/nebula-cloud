"""
Tests for password change functionality.

This module tests the PasswordChangeView endpoint:
- POST /api/auth/password/change/

Tests cover:
- Successful password change
- Validation errors (current password, confirmation, strength)
- Authentication requirements
- Edge cases and security scenarios
"""

# pylint: disable=unused-argument
# pylint: disable=redefined-outer-name

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status

User = get_user_model()


class TestPasswordChangeView:
    """Test cases for PasswordChangeView endpoint."""

    def test_password_change_success(
        self, authenticated_client, user_account, valid_password_change_data
    ):
        """Test successful password change with valid data."""
        url = reverse("users:password_change")

        response = authenticated_client.post(url, valid_password_change_data)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Пароль успешно изменён."

        # Verify new password works by logging in
        login_response = authenticated_client.post(
            reverse("users:login"),
            {
                "username": user_account.username,
                "password": valid_password_change_data["new_password"],
            },
        )
        assert login_response.status_code == status.HTTP_200_OK

        # Verify old password no longer works
        old_password_response = authenticated_client.post(
            reverse("users:login"),
            {
                "username": user_account.username,
                "password": valid_password_change_data["current_password"],
            },
        )
        assert old_password_response.status_code == status.HTTP_400_BAD_REQUEST

    def test_password_change_wrong_current_password(
        self, authenticated_client, wrong_current_password_data
    ):
        """Test password change with incorrect current password."""
        url = reverse("users:password_change")

        response = authenticated_client.post(url, wrong_current_password_data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "current_password" in response.data
        assert any(
            "неверный" in str(msg).lower() or "wrong" in str(msg).lower()
            for msg in response.data["current_password"]
        )

    def test_password_change_mismatch_confirmation(
        self, authenticated_client, invalid_password_change_data
    ):
        """Test password change with mismatched password confirmation."""
        url = reverse("users:password_change")

        response = authenticated_client.post(url, invalid_password_change_data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "new_password_confirm" in response.data

    def test_password_change_same_as_current(self, authenticated_client, user_account):
        """Test password change with new password same as current."""
        url = reverse("users:password_change")
        data = {
            "current_password": "TestPass123!",
            "new_password": "TestPass123!",
            "new_password_confirm": "TestPass123!",
        }

        response = authenticated_client.post(url, data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "new_password" in response.data

    def test_password_change_weak_password(self, authenticated_client, weak_password_change_data):
        """Test password change with weak new password."""
        url = reverse("users:password_change")

        response = authenticated_client.post(url, weak_password_change_data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "new_password" in response.data
        # Check that validation messages are returned
        assert isinstance(response.data["new_password"], list)
        assert len(response.data["new_password"]) > 0

    def test_password_change_unauthenticated(self, api_client, valid_password_change_data):
        """Test password change without authentication returns 401."""
        url = reverse("users:password_change")

        response = api_client.post(url, valid_password_change_data)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_password_change_missing_fields(self, authenticated_client):
        """Test password change with missing required fields."""
        url = reverse("users:password_change")
        data = {
            "current_password": "TestPass123!",
            # Missing new_password and new_password_confirm
        }

        response = authenticated_client.post(url, data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "new_password" in response.data
        assert "new_password_confirm" in response.data

    def test_password_change_invalid_token(self, api_client, valid_password_change_data):
        """Test password change with invalid/expired JWT token."""
        url = reverse("users:password_change")

        api_client.credentials(HTTP_AUTHORIZATION="Bearer invalid_token_xyz")
        response = api_client.post(url, valid_password_change_data)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_password_change_inactive_user(
        self, api_client, inactive_user_account, valid_password_change_data
    ):
        """Test password change attempt by inactive user."""
        # Login inactive user
        login_response = api_client.post(
            reverse("users:login"),
            {
                "username": inactive_user_account.username,
                "password": "InactivePass123!",
            },
        )
        # Login should fail for inactive user
        assert login_response.status_code == status.HTTP_400_BAD_REQUEST

    def test_password_change_admin_user(self, admin_client, valid_password_change_data):
        """Test that admin users can change their own password."""

        url = reverse("users:password_change")

        data = {
            "current_password": "AdminPass123!",
            "new_password": "NewAdminPass456!",
            "new_password_confirm": "NewAdminPass456!",
        }

        response = admin_client.post(url, data)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Пароль успешно изменён."

        # Verify admin can still login with new password
        login_response = admin_client.post(
            reverse("users:login"),
            {
                "username": admin_client.user.username,
                "password": data["new_password"],
            },
        )
        assert login_response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
class TestPasswordChangeValidation:
    """Test password validation rules during password change."""

    def test_password_minimum_length(self, authenticated_client):
        """Test password change rejects password shorter than minimum length."""
        url = reverse("users:password_change")
        data = {
            "current_password": "TestPass123!",
            "new_password": "Ab1!",
            "new_password_confirm": "Ab1!",
        }

        response = authenticated_client.post(url, data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "new_password" in response.data

    def test_password_requires_uppercase(self, authenticated_client):
        """Test password change requires at least one uppercase letter."""
        url = reverse("users:password_change")
        # Password with no uppercase - should fail
        data = {
            "current_password": "TestPass123!",
            "new_password": "newpass123!abc",  # No uppercase
            "new_password_confirm": "newpass123!abc",
        }

        response = authenticated_client.post(url, data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "new_password" in response.data

    def test_password_requires_lowercase(self, authenticated_client):
        """Test password change requires at least one lowercase letter."""
        url = reverse("users:password_change")
        # Password with no lowercase - should fail
        data = {
            "current_password": "TestPass123!",
            "new_password": "NEWPASS123!ABC",  # No lowercase
            "new_password_confirm": "NEWPASS123!ABC",
        }

        response = authenticated_client.post(url, data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "new_password" in response.data

    def test_password_requires_digit(self, authenticated_client):
        """Test password change requires at least one digit."""
        url = reverse("users:password_change")
        # Password with no digit - should fail
        data = {
            "current_password": "TestPass123!",
            "new_password": "Newpassabc!!!",  # No digit
            "new_password_confirm": "Newpassabc!!!",
        }

        response = authenticated_client.post(url, data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "new_password" in response.data

    def test_password_requires_special_char(self, authenticated_client):
        """Test password change requires at least one special character."""
        url = reverse("users:password_change")
        # Password with no special char - should fail
        data = {
            "current_password": "TestPass123!",
            "new_password": "NewPass1234abc",  # No special character
            "new_password_confirm": "NewPass1234abc",
        }

        response = authenticated_client.post(url, data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "new_password" in response.data

    def test_password_change_empty_fields(self, authenticated_client):
        """Test password change with empty string fields."""
        url = reverse("users:password_change")
        data = {
            "current_password": "",
            "new_password": "",
            "new_password_confirm": "",
        }

        response = authenticated_client.post(url, data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "current_password" in response.data
        assert "new_password" in response.data
        assert "new_password_confirm" in response.data


class TestPasswordChangeMethodNotAllowed:
    """Test HTTP method restrictions for password change endpoint."""

    def test_password_change_get_not_allowed(self, authenticated_client):
        """Test that GET request to password change endpoint returns 405."""
        url = reverse("users:password_change")

        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_password_change_put_not_allowed(
        self, authenticated_client, valid_password_change_data
    ):
        """Test that PUT request to password change endpoint returns 405."""
        url = reverse("users:password_change")

        response = authenticated_client.put(url, valid_password_change_data)

        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_password_change_delete_not_allowed(self, authenticated_client):
        """Test that DELETE request to password change endpoint returns 405."""
        url = reverse("users:password_change")

        response = authenticated_client.delete(url)

        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
