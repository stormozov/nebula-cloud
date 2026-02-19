"""
Pytest fixtures for users application tests.

This module provides reusable test fixtures for:
- User accounts (regular and admin)
- Authentication tokens (JWT)
- API clients with different authentication states
- Password change test data

Usage:
    from users.tests.conftest import user_account, authenticated_client
"""

# pylint: disable=unused-argument
# pylint: disable=redefined-outer-name

import uuid

import pytest
from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from storage.models import File

User = get_user_model()


# ==============================================================================
# FIXTURES: USERS
# ==============================================================================


@pytest.fixture
def user_account(db):
    """
    Create a regular user account for testing.

    Uses unique username to avoid conflicts between test runs.

    Returns:
        UserAccount: Regular user instance with test credentials.
    """
    unique_id = uuid.uuid4().hex[:8]
    return User.objects.create_user(
        username=f"testuser_{unique_id}",
        email=f"testuser_{unique_id}@example.com",
        password="TestPass123!",
        first_name="Test",
        last_name="User",
    )


@pytest.fixture
def admin_account(db):
    """
    Create an admin user account for testing.

    Uses unique username to avoid conflicts between test runs.

    Returns:
        UserAccount: Admin user instance with is_staff=True.
    """
    unique_id = uuid.uuid4().hex[:8]
    return User.objects.create_user(
        username=f"adminuser_{unique_id}",
        email=f"admin_{unique_id}@example.com",
        password="AdminPass123!",
        first_name="Admin",
        last_name="User",
        is_staff=True,
    )


@pytest.fixture
def inactive_user_account(db):
    """
    Create an inactive user account for testing authentication edge cases.

    Returns:
        UserAccount: Inactive user instance with is_active=False.
    """
    unique_id = uuid.uuid4().hex[:8]
    return User.objects.create_user(
        username=f"inactive_{unique_id}",
        email=f"inactive_{unique_id}@example.com",
        password="InactivePass123!",
        first_name="Inactive",
        last_name="User",
        is_active=False,
    )


# ==============================================================================
# FIXTURES: AUTHENTICATION
# ==============================================================================


@pytest.fixture
def api_client():
    """
    Create an unauthenticated API client for testing.

    Returns:
        APIClient: DRF test client without authentication headers.
    """
    return APIClient()


@pytest.fixture
def authenticated_client(api_client, user_account):
    """
    Create an authenticated API client for regular user.

    Automatically sets JWT Authorization header for all requests.

    Args:
        api_client: Unauthenticated APIClient fixture.
        user_account: Regular user fixture.

    Returns:
        APIClient: DRF test client with valid JWT access token.
    """
    refresh = RefreshToken.for_user(user_account)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    api_client.user = user_account
    return api_client


@pytest.fixture
def admin_client(api_client, admin_account):
    """
    Create an authenticated API client for admin user.

    Automatically sets JWT Authorization header with admin privileges.

    Args:
        api_client: Unauthenticated APIClient fixture.
        admin_account: Admin user fixture.

    Returns:
        APIClient: DRF test client with admin JWT access token.
    """
    refresh = RefreshToken.for_user(admin_account)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    api_client.user = admin_account
    return api_client


@pytest.fixture
def expired_token_client(api_client, user_account):
    """
    Create an API client with an expired JWT token for testing token validation.

    Args:
        api_client: Unauthenticated APIClient fixture.
        user_account: Regular user fixture.

    Returns:
        APIClient: DRF test client with expired token.
    """
    refresh = RefreshToken.for_user(user_account)
    expired_token = str(refresh.access_token)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {expired_token}")
    return api_client


# ==============================================================================
# FIXTURES: PASSWORD CHANGE TEST DATA
# ==============================================================================


@pytest.fixture
def valid_password_change_data():
    """
    Provide valid password change request data.

    Returns:
        dict: Valid payload for password change endpoint.
    """
    return {
        "current_password": "TestPass123!",
        "new_password": "NewSecurePass456!",
        "new_password_confirm": "NewSecurePass456!",
    }


@pytest.fixture
def invalid_password_change_data():
    """
    Provide invalid password change request data (mismatched confirmation).

    Returns:
        dict: Invalid payload with mismatched passwords.
    """
    return {
        "current_password": "TestPass123!",
        "new_password": "NewSecurePass456!",
        "new_password_confirm": "DifferentPass789!",
    }


@pytest.fixture
def weak_password_change_data():
    """
    Provide password change data with weak new password.

    Returns:
        dict: Payload with password that fails Django validators.
    """
    return {
        "current_password": "TestPass123!",
        "new_password": "weak",
        "new_password_confirm": "weak",
    }


@pytest.fixture
def wrong_current_password_data():
    """
    Provide password change data with incorrect current password.

    Returns:
        dict: Payload with wrong current password.
    """
    return {
        "current_password": "WrongPass999!",
        "new_password": "NewSecurePass456!",
        "new_password_confirm": "NewSecurePass456!",
    }


@pytest.fixture
def valid_password_data():
    """
    Provide valid password data that meets all validation requirements.

    Returns:
        dict: Valid password payload.
    """
    return {
        "new_password": "ValidPass123!",
        "new_password_confirm": "ValidPass123!",
    }


@pytest.fixture
def weak_password_data():
    """
    Provide weak password data that fails validation.

    Returns:
        dict: Weak password payload.
    """
    return {
        "new_password": "weak",
        "new_password_confirm": "weak",
    }


# ==============================================================================
# FIXTURES: HELPERS
# ==============================================================================


@pytest.fixture
def login_user(api_client):
    """
    Helper fixture to perform login and return authenticated client + tokens.

    Usage:
        def test_something(login_user):
            client, tokens, user = login_user("username", "password")

    Returns:
        callable: Function that logs in a user and returns (client, tokens, user).
    """

    def _login(username: str, password: str):
        response = api_client.post(
            "/api/auth/login/",
            {"username": username, "password": password},
        )

        if response.status_code == 200:
            tokens = response.data
            user = User.objects.get(username=username)
            api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
            api_client.user = user

            return api_client, tokens, user

        return None, response.data, None

    return _login


@pytest.fixture
def create_test_user(db):
    """
    Factory fixture for creating UserAccount instances directly.
    Bypasses serializers for unit testing.

    Returns:
        callable: Function that creates UserAccount instances.

    Example:
        user = create_test_user(
            username="custom_user",
            email="custom@example.com",
            password="CustomPass123!",
            is_staff=True
        )
    """

    def _create_user(
        username=None,
        email=None,
        password="DefaultPass123!",
        first_name="Test",
        last_name="User",
        is_staff=False,
        is_active=True,
    ):
        unique_id = uuid.uuid4().hex[:8]
        return User.objects.create_user(
            username=username or f"user_{unique_id}",
            email=email or f"user_{unique_id}@example.com",
            password=password,
            first_name=first_name,
            last_name=last_name,
            is_staff=is_staff,
            is_active=is_active,
        )

    return _create_user


# ==============================================================================
# FIXTURES: STORAGE (for admin tests)
# ==============================================================================


@pytest.fixture
def test_file_for_users():
    """
    Create a temporary test file for upload testing.
    Local version for users app tests (doesn't depend on storage fixtures).

    Returns:
        SimpleUploadedFile: Test file object.
    """

    file_content = b"Test file content for storage application testing." * 20
    return SimpleUploadedFile(
        name="test_file.txt",
        content=file_content,
        content_type="text/plain",
    )


@pytest.fixture
def uploaded_file(db, user_account, test_file_for_users):
    """
    Create an uploaded file in the database for testing.
    Creates file directly in DB to avoid API client state conflicts.

    Args:
        db: Pytest database fixture.
        user_account: Regular user fixture.
        test_file_for_users: Local test file fixture.

    Returns:
        File: Saved File model instance.
    """

    # Read file content and reset pointer
    file_content = test_file_for_users.read()
    test_file_for_users.seek(0)

    # Create file directly in database
    file_obj = File(
        owner=user_account,
        original_name=test_file_for_users.name,
        size=len(file_content),
        comment="Test comment for uploaded file",
    )
    file_obj.file.save(  # pylint: disable=no-member
        test_file_for_users.name,
        ContentFile(file_content),
        save=True,
    )

    return file_obj


@pytest.fixture
def admin_uploaded_file(db, admin_account, test_file_for_users):
    """
    Create an uploaded file by admin user for testing.
    Creates file directly in DB to avoid API client state conflicts.
    """

    file_content = test_file_for_users.read()
    test_file_for_users.seek(0)

    file_obj = File(
        owner=admin_account,
        original_name=test_file_for_users.name,
        size=len(file_content),
        comment="Admin test comment",
    )
    file_obj.file.save(  # pylint: disable=no-member
        test_file_for_users.name,
        ContentFile(file_content),
        save=True,
    )

    return file_obj
