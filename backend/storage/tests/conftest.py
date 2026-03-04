"""
Pytest fixtures for storage application tests.

This module provides reusable test fixtures for:
- User accounts (regular and admin)
- Authentication tokens
- Test files
- API clients
- Temporary media storage
- FileViewSet testing helpers
"""

# pylint: disable=unused-argument
# pylint: disable=no-member

import tempfile
import shutil
import uuid
from pathlib import Path

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.files.storage import FileSystemStorage
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from storage.models import File

User = get_user_model()


# ==================================================================================================
# FIXTURES: SETTINGS & STORAGE
# ==================================================================================================


@pytest.fixture(autouse=True)
def media_root_tmp(monkeypatch, tmp_path: Path):
    """
    Override MEDIA_ROOT to use temporary directory for tests.

    Automatically applied to all tests. Ensures uploaded files are stored
    in isolated temp directory and cleaned up after test run.

    Args:
        monkeypatch: Pytest monkeypatch fixture for overriding settings.
        tmp_path: Pytest built-in temporary path fixture.

    Yields:
        Path: Temporary media root directory path.
    """

    # Create temporary directory
    temp_media = Path(tempfile.mkdtemp(prefix="test_media_"))

    # Override MEDIA_ROOT
    settings.MEDIA_ROOT = str(temp_media)

    yield

    # Cleanup after all tests
    shutil.rmtree(temp_media, ignore_errors=True)


# ==================================================================================================
# FIXTURES: USERS
# ==================================================================================================


@pytest.fixture
def user_account(db):
    """
    Create a regular user account for testing.

    Uses unique username to avoid conflicts between test runs.

    Args:
        db: Pytest database fixture.

    Returns:
        User: Regular user instance.
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

    Args:
        db: Pytest database fixture.

    Returns:
        User: Admin user instance with is_staff=True.
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

    Args:
        db: Pytest database fixture.

    Returns:
        User: Another regular user instance.
    """
    unique_id = uuid.uuid4().hex[:8]
    return User.objects.create_user(
        username=f"anotheruser_{unique_id}",
        email=f"another_{unique_id}@example.com",
        password="AnotherPass123!",
        first_name="Another",
        last_name="User",
    )


# ==================================================================================================
# FIXTURES: AUTHENTICATION
# ==================================================================================================


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


# ==================================================================================================
# FIXTURES: FILES
# ==================================================================================================


@pytest.fixture
def test_file() -> SimpleUploadedFile:
    """
    Create a temporary test file for upload testing.

    Returns:
        SimpleUploadedFile: Test file object (~1KB of data).
    """
    file_content = b"Test file content for storage application testing. " * 20
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
    file_content = b"x" * (settings.MAX_UPLOAD_SIZE + 1)
    return SimpleUploadedFile(
        name="large_file.bin",
        content=file_content,
        content_type="application/octet-stream",
    )


@pytest.fixture
def uploaded_file(authenticated_client, test_file) -> File | None:
    """
    Create an uploaded file via standard ViewSet create endpoint.

    Posts to `/api/storage/files/` (standard DRF create action).

    Args:
        authenticated_client: Authenticated APIClient fixture.
        test_file: Test file fixture.

    Returns:
        File | None: Saved File model instance or None if upload failed.
    """

    upload_data = {
        "file": test_file,
        "comment": "Test comment for uploaded file",
    }

    response = authenticated_client.post("/api/storage/files/", upload_data, format="multipart")

    return File.objects.get(id=response.data["id"]) if response.status_code == 201 else None


@pytest.fixture
def uploaded_file_via_action(authenticated_client, test_file) -> File | None:
    """
    Create an uploaded file via custom @action endpoint.

    Posts to `/api/storage/files/upload/` (custom upload action).

    Args:
        authenticated_client: Authenticated APIClient fixture.
        test_file: Test file fixture.

    Returns:
        File | None: Saved File model instance or None if upload failed.
    """

    upload_data = {
        "file": test_file,
        "comment": "Test comment via upload action",
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
        File | None: Saved File model instance or None if upload failed.
    """

    upload_data = {
        "file": test_file,
        "comment": "Admin test comment",
    }

    response = admin_client.post("/api/storage/files/", upload_data, format="multipart")

    return File.objects.get(id=response.data["id"]) if response.status_code == 201 else None


@pytest.fixture
def file_with_public_link(create_file, user_account) -> File:
    """
    Create a file with an active public link for testing.

    Args:
        create_file: File factory fixture.
        user_account: Regular user fixture.

    Returns:
        File: File instance with generated public_link.
    """

    file_obj = create_file(
        owner=user_account,
        original_name="public_doc.pdf",
        size=2048,
        comment="File with public access",
    )
    file_obj.generate_public_link(force=True)
    file_obj.save(update_fields=["public_link"])

    return file_obj


@pytest.fixture
def multiple_files(create_file, user_account) -> list[File]:
    """
    Create multiple files for list endpoint testing.

    Args:
        create_file: File factory fixture.
        user_account: Regular user fixture.

    Returns:
        list[File]: List of 5 file instances owned by user.
    """
    return [
        create_file(
            owner=user_account,
            original_name=f"file_{i}.txt",
            size=100 * (i + 1),
            comment=f"Test file #{i}",
        )
        for i in range(5)
    ]


@pytest.fixture
def another_user_file(create_file, another_user_account) -> File:
    """
    Create a file owned by another user for permission testing.

    Args:
        create_file: File factory fixture.
        another_user_account: Another user fixture.

    Returns:
        File: File instance owned by different user.
    """
    return create_file(
        owner=another_user_account,
        original_name="others_file.txt",
        size=512,
        comment="File owned by another user",
    )


# ==================================================================================================
# FIXTURES: HELPERS
# ==================================================================================================


@pytest.fixture
def create_file(db, user_account):
    """
    Factory fixture for creating File instances directly in database.

    Bypasses API for unit testing models. File content is minimal test data.

    Args:
        db: Pytest database fixture.
        user_account: Regular user fixture (default owner).

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
        owner: User | None = None,
        original_name: str = "test.txt",
        size: int = 100,
        comment: str = "",
        public_link: str | None = None,
    ) -> File:
        file_obj = File(
            owner=owner or user_account,
            original_name=original_name,
            size=size,
            comment=comment,
            public_link=public_link,
        )
        file_obj.file.save(
            original_name,
            ContentFile(b"Test content for pytest"),
            save=True,
        )
        return file_obj

    return _create_file


@pytest.fixture
def viewset_base_url() -> str:
    """
    Base URL prefix for FileViewSet endpoints.

    Returns:
        str: Base URL path for file operations.
    """
    return "/api/storage/files"


@pytest.fixture
def file_endpoints(viewset_base_url) -> dict[str, str]:
    """
    Dictionary of FileViewSet endpoint URL templates for testing.

    Returns:
        dict[str, str]: Mapping of action names to URL patterns.

    Example:
        url = file_endpoints["list"]  # "/api/storage/files/"
        url = file_endpoints["detail"].format(pk=file_id)  # "/api/storage/files/{id}/"
    """
    return {
        "list": f"{viewset_base_url}/",
        "detail": f"{viewset_base_url}/{{pk}}/",
        "upload_action": f"{viewset_base_url}/upload/",
        "download": f"{viewset_base_url}/{{pk}}/download/",
        "rename": f"{viewset_base_url}/{{pk}}/rename/",
        "comment": f"{viewset_base_url}/{{pk}}/comment/",
        "public_link_generate": f"{viewset_base_url}/{{pk}}/public-link/generate/",
        "public_link_delete": f"{viewset_base_url}/{{pk}}/public-link/",
    }
