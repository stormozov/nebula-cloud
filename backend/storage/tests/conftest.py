"""
Pytest fixtures for storage application tests.

This module provides reusable test fixtures for:
- User accounts (regular and admin)
- Authentication tokens
- Test files
- API clients
- Temporary media storage
"""

# pylint: disable=unused-argument
# pylint: disable=no-member

import shutil
import tempfile
import uuid

import pytest
from django.conf import settings
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
        UserAccount: Regular user instance.
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
def another_user_account(db):
    """
    Create a second regular user for permission testing.

    Uses unique username to avoid conflicts between test runs.

    Returns:
        UserAccount: Another regular user instance.
    """
    unique_id = uuid.uuid4().hex[:8]
    return User.objects.create_user(
        username=f"anotheruser_{unique_id}",
        email=f"another_{unique_id}@example.com",
        password="AnotherPass123!",
        first_name="Another",
        last_name="User",
    )


# ==============================================================================
# FIXTURES: AUTHENTICATION
# ==============================================================================


@pytest.fixture
def api_client():
    """
    Create an unauthenticated API client for testing.

    Returns:
        APIClient: DRF test client without authentication.
    """
    return APIClient()


@pytest.fixture
def authenticated_client(api_client, user_account):
    """
    Create an authenticated API client for regular user.

    Args:
        api_client: Unauthenticated APIClient fixture.
        user_account: Regular user fixture.

    Returns:
        APIClient: DRF test client with JWT authentication.
    """

    refresh = RefreshToken.for_user(user_account)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    api_client.user = user_account

    return api_client


@pytest.fixture
def admin_client(api_client, admin_account):
    """
    Create an authenticated API client for admin user.

    Args:
        api_client: Unauthenticated APIClient fixture.
        admin_account: Admin user fixture.

    Returns:
        APIClient: DRF test client with JWT authentication (admin).
    """

    refresh = RefreshToken.for_user(admin_account)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    api_client.user = admin_account

    return api_client


# ==============================================================================
# FIXTURES: FILES
# ==============================================================================


@pytest.fixture
def test_file():
    """
    Create a temporary test file for upload testing.

    Returns:
        SimpleUploadedFile: Test file object (1KB of data).
    """
    file_content = b"Test file content for storage application testing." * 20
    return SimpleUploadedFile(
        name="test_file.txt",
        content=file_content,
        content_type="text/plain",
    )


@pytest.fixture
def test_image_file() -> SimpleUploadedFile:
    """
    Create a temporary test image file for upload testing.

    Returns:
        SimpleUploadedFile: Test image file object (PNG header).
    """
    # Minimal PNG header (valid PNG signature)
    file_content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100  # PNG signature + padding
    return SimpleUploadedFile(
        name="test_image.png",
        content=file_content,
        content_type="image/png",
    )


@pytest.fixture
def large_test_file() -> SimpleUploadedFile:
    """
    Create a large test file (exceeds 100MB limit) for validation testing.

    Returns:
        SimpleUploadedFile: Large file object (~101MB).
    """
    # Create 101MB of data (exceeds 100MB limit)
    file_content = b"x" * (101 * 1024 * 1024)
    return SimpleUploadedFile(
        name="large_file.bin",
        content=file_content,
        content_type="application/octet-stream",
    )


@pytest.fixture
def uploaded_file(authenticated_client, test_file) -> File | None:
    """
    Create an uploaded file in the database for testing.

    Args:
        authenticated_client: Authenticated APIClient fixture.
        test_file: Test file fixture.

    Returns:
        File: Saved File model instance.
    """

    upload_data = {
        "file": test_file,
        "comment": "Test comment for uploaded file",
    }

    response = authenticated_client.post(
        "/api/storage/files/upload/", upload_data, format="multipart"
    )

    return File.objects.get(id=response.data["id"]) if response.status_code == 201 else None


@pytest.fixture
def admin_uploaded_file(admin_client, test_file) -> File | None:
    """
    Create an uploaded file by admin user for testing.

    Args:
        admin_client: Authenticated admin APIClient fixture.
        test_file: Test file fixture.

    Returns:
        File: Saved File model instance.
    """

    upload_data = {
        "file": test_file,
        "comment": "Admin test comment",
    }

    response = admin_client.post("/api/storage/files/upload/", upload_data, format="multipart")

    return File.objects.get(id=response.data["id"]) if response.status_code == 201 else None


# ==============================================================================
# FIXTURES: HELPERS
# ==============================================================================


@pytest.fixture
def create_file(db, user_account):
    """
    Factory fixture for creating File instances directly in database.
    Bypasses API for unit testing models.

    Args:
        db: Pytest database fixture.
        user_account: Regular user fixture.

    Returns:
        callable: Function that creates File instances.

    Example:
        file = create_file(
            owner=user_account,
            original_name="document.pdf",
            size=1024
        )
    """

    def _create_file(
        owner=None,
        original_name="test.txt",
        size=100,
        comment="",
        public_link=None,
    ):
        file_obj = File(
            owner=owner or user_account,
            original_name=original_name,
            size=size,
            comment=comment,
            public_link=public_link,
        )
        file_obj.file.save(
            original_name,
            ContentFile(b"Test content"),
            save=True,
        )
        return file_obj

    return _create_file
