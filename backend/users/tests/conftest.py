"""
Pytest fixtures for users application tests.

This module provides reusable test fixtures for:
- User accounts (regular, admin, inactive, multiple users)
- Authentication tokens (JWT)
- API clients with different authentication states
- Admin user management actions (password reset, toggle admin, storage stats)
- File storage operations

Fixtures are organized by category:
1. Users - User account fixtures
2. Authentication - API client and token fixtures
3. Admin Actions - Data fixtures for admin operations
4. URLs - URL generation helpers for ViewSet routing
5. Helpers - Utility functions for test setup
6. Storage - File storage fixtures for integration tests
"""

import uuid
from typing import Callable, Dict, List, Optional, Tuple, Any

import pytest
from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from storage.models import File

User = get_user_model()

# ==================================================================================================
# CONSTANTS
# ==================================================================================================

DEFAULT_TEST_PASSWORD = "TestPass123!"
DEFAULT_ADMIN_PASSWORD = "AdminPass123!"
ADMIN_URL_BASE = "/api/admin/users/"

# ==================================================================================================
# FIXTURES: USERS
# ==================================================================================================


@pytest.fixture
def user_account(db) -> User:
    """
    Create a regular user account for testing.

    Uses unique username to avoid conflicts between test runs.

    Returns:
        User: Regular user instance with test credentials.

    Example:
        def test_something(user_account):
            assert user_account.is_staff is False
    """
    unique_id = uuid.uuid4().hex[:8]
    return User.objects.create_user(
        username=f"testuser_{unique_id}",
        email=f"testuser_{unique_id}@example.com",
        password=DEFAULT_TEST_PASSWORD,
        first_name="Test",
        last_name="User",
        is_staff=False,
        is_active=True,
    )


@pytest.fixture
def admin_account(db) -> User:
    """
    Create an admin user account for testing.

    Uses unique username to avoid conflicts between test runs.
    Has is_staff=True for admin permissions.

    Returns:
        User: Admin user instance with is_staff=True.

    Example:
        def test_admin_action(admin_account):
            assert admin_account.is_staff is True
    """
    unique_id = uuid.uuid4().hex[:8]
    return User.objects.create_user(
        username=f"adminuser_{unique_id}",
        email=f"admin_{unique_id}@example.com",
        password=DEFAULT_ADMIN_PASSWORD,
        first_name="Admin",
        last_name="User",
        is_staff=True,
        is_active=True,
    )


@pytest.fixture
def inactive_user_account(db) -> User:
    """
    Create an inactive user account for testing authentication edge cases.

    Returns:
        User: Inactive user instance with is_active=False.

    Example:
        def test_inactive_login(inactive_user_account):
            assert inactive_user_account.is_active is False
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


@pytest.fixture
def target_user_account(db, create_test_user: Callable) -> User:
    """
    Create a target user account for admin action testing.

    This fixture represents a user that an admin will perform actions on
    (e.g., password reset, toggle admin status, delete).

    Args:
        db: Pytest database fixture.
        create_test_user: Factory fixture for creating users.

    Returns:
        User: Target user instance for admin operations.

    Example:
        def test_admin_delete_user(admin_client, target_user_account):
            response = admin_client.delete(
                f"/api/users/admin/users/{target_user_account.id}/"
            )
            assert response.status_code == 200
    """
    return create_test_user(
        username="target_user",
        email="target@example.com",
        password="TargetPass123!",
        is_staff=False,
    )


@pytest.fixture
def multiple_user_accounts(db, create_test_user: Callable) -> List[User]:
    """
    Create multiple user accounts for list and bulk operation testing.

    Creates 3 regular users for testing list pagination and filtering.

    Args:
        db: Pytest database fixture.
        create_test_user: Factory fixture for creating users.

    Returns:
        List[User]: List of 3 user instances.

    Example:
        def test_user_list(admin_client, multiple_user_accounts):
            response = admin_client.get("/api/users/admin/users/")
            assert len(response.data) >= 3
    """
    return [
        create_test_user(
            username=f"multi_user_{i}",
            email=f"multi_{i}@example.com",
            password=DEFAULT_TEST_PASSWORD,
        )
        for i in range(3)
    ]


@pytest.fixture
def second_admin_account(db, create_test_user: Callable) -> User:
    """
    Create a second admin user for testing admin-to-admin actions.

    Useful for testing edge cases like admin trying to modify another admin.

    Args:
        db: Pytest database fixture.
        create_test_user: Factory fixture for creating users.

    Returns:
        User: Second admin user instance.

    Example:
        def test_admin_modify_another_admin(admin_client, second_admin_account):
            response = admin_client.post(
                f"/api/users/admin/users/{second_admin_account.id}/toggle-admin/",
                {"is_admin": False}
            )
            assert response.status_code == 200
    """
    return create_test_user(
        username="second_admin",
        email="second_admin@example.com",
        password=DEFAULT_ADMIN_PASSWORD,
        is_staff=True,
    )


# ==================================================================================================
# FIXTURES: AUTHENTICATION
# ==================================================================================================


@pytest.fixture
def api_client() -> APIClient:
    """
    Create an unauthenticated API client for testing.

    Returns:
        APIClient: DRF test client without authentication headers.

    Example:
        def test_unauthenticated_access(api_client):
            response = api_client.get("/api/users/admin/users/")
            assert response.status_code == 401
    """
    return APIClient()


@pytest.fixture
def authenticated_client(api_client: APIClient, user_account: User) -> APIClient:
    """
    Create an authenticated API client for regular user.

    Automatically sets JWT Authorization header for all requests.

    Args:
        api_client: Unauthenticated APIClient fixture.
        user_account: Regular user fixture.

    Returns:
        APIClient: DRF test client with valid JWT access token.
        Client has `user` attribute set for reference.

    Example:
        def test_user_profile(authenticated_client):
            response = authenticated_client.get("/api/users/users/me/")
            assert response.status_code == 200
    """
    refresh = RefreshToken.for_user(user_account)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    api_client.user = user_account  # type: ignore
    return api_client


@pytest.fixture
def admin_client(api_client: APIClient, admin_account: User) -> APIClient:
    """
    Create an authenticated API client for admin user.

    Automatically sets JWT Authorization header with admin privileges.

    Args:
        api_client: Unauthenticated APIClient fixture.
        admin_account: Admin user fixture.

    Returns:
        APIClient: DRF test client with admin JWT access token.
        Client has `user` attribute set for reference.

    Example:
        def test_admin_user_list(admin_client):
            response = admin_client.get("/api/users/admin/users/")
            assert response.status_code == 200
    """
    refresh = RefreshToken.for_user(admin_account)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    api_client.user = admin_account  # type: ignore
    return api_client


@pytest.fixture
def expired_token_client(api_client: APIClient, user_account: User) -> APIClient:
    """
    Create an API client with an expired JWT token for testing token validation.

    Note: In real testing, you may need to manipulate token expiration
    or use time mocking for proper expired token testing.

    Args:
        api_client: Unauthenticated APIClient fixture.
        user_account: Regular user fixture.

    Returns:
        APIClient: DRF test client with token (may need time mocking for expiry).
    """
    refresh = RefreshToken.for_user(user_account)
    expired_token = str(refresh.access_token)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {expired_token}")
    return api_client


@pytest.fixture
def unauthorized_client(api_client: APIClient) -> APIClient:
    """
    Create an API client with invalid token for testing authorization failures.

    Args:
        api_client: Unauthenticated APIClient fixture.

    Returns:
        APIClient: DRF test client with invalid token.

    Example:
        def test_invalid_token(unauthorized_client):
            response = unauthorized_client.get("/api/users/admin/users/")
            assert response.status_code == 401
    """
    api_client.credentials(HTTP_AUTHORIZATION="Bearer invalid_token_here")
    return api_client


# ==================================================================================================
# FIXTURES: ADMIN ACTIONS DATA
# ==================================================================================================


@pytest.fixture
def password_reset_data() -> Dict[str, str]:
    """
    Provide valid password reset request data for admin endpoint.

    Returns:
        dict: Valid payload for admin password reset endpoint.

    Example:
        def test_password_reset(admin_client, target_user_account, password_reset_data):
            response = admin_client.post(
                f"/api/users/admin/users/{target_user_account.id}/password/",
                password_reset_data
            )
            assert response.status_code == 200
    """
    return {
        "new_password": "NewSecurePass456!",
        "new_password_confirm": "NewSecurePass456!",
    }


@pytest.fixture
def weak_password_reset_data() -> Dict[str, str]:
    """
    Provide weak password reset data that fails validation.

    Returns:
        dict: Invalid payload with weak password.

    Example:
        def test_weak_password_rejected(admin_client, target_user_account, weak_password_reset_data):
            response = admin_client.post(
                f"/api/users/admin/users/{target_user_account.id}/password/",
                weak_password_reset_data
            )
            assert response.status_code == 400
    """
    return {
        "new_password": "weak",
        "new_password_confirm": "weak",
    }


@pytest.fixture
def mismatched_password_reset_data() -> Dict[str, str]:
    """
    Provide password reset data with mismatched confirmation.

    Returns:
        dict: Invalid payload with mismatched passwords.

    Example:
        def test_mismatched_password(admin_client, target_user_account, mismatched_password_reset_data):
            response = admin_client.post(
                f"/api/users/admin/users/{target_user_account.id}/password/",
                mismatched_password_reset_data
            )
            assert response.status_code == 400
    """
    return {
        "new_password": "NewSecurePass456!",
        "new_password_confirm": "DifferentPass789!",
    }


@pytest.fixture
def toggle_admin_data_enable() -> Dict[str, bool]:
    """
    Provide data for enabling admin status.

    Returns:
        dict: Payload for setting is_admin=True.

    Example:
        def test_enable_admin(admin_client, target_user_account, toggle_admin_data_enable):
            response = admin_client.post(
                f"/api/users/admin/users/{target_user_account.id}/toggle-admin/",
                toggle_admin_data_enable
            )
            assert response.data["is_admin"] is True
    """
    return {"is_admin": True}


@pytest.fixture
def toggle_admin_data_disable() -> Dict[str, bool]:
    """
    Provide data for disabling admin status.

    Returns:
        dict: Payload for setting is_admin=False.

    Example:
        def test_disable_admin(admin_client, second_admin_account, toggle_admin_data_disable):
            response = admin_client.post(
                f"/api/users/admin/users/{second_admin_account.id}/toggle-admin/",
                toggle_admin_data_disable
            )
            assert response.data["is_admin"] is False
    """
    return {"is_admin": False}


@pytest.fixture
def invalid_toggle_admin_data() -> Dict[str, Any]:
    """
    Provide invalid toggle admin data for validation testing.

    Returns:
        dict: Invalid payload with wrong type.

    Example:
        def test_invalid_toggle_data(admin_client, target_user_account, invalid_toggle_admin_data):
            response = admin_client.post(
                f"/api/users/admin/users/{target_user_account.id}/toggle-admin/",
                invalid_toggle_admin_data
            )
            assert response.status_code == 400
    """
    return {"is_admin": "not_a_boolean"}


# ==================================================================================================
# FIXTURES: URLs
# ==================================================================================================


@pytest.fixture
def admin_user_url() -> Callable[[int], str]:
    """
    Generate admin user detail URL for ViewSet.

    Returns:
        Callable[[int], str]: Function that takes user ID and returns URL.

    Example:
        def test_user_detail(admin_client, target_user_account, admin_user_url):
            url = admin_user_url(target_user_account.id)
            response = admin_client.get(url)
            assert response.status_code == 200
    """

    def _get_url(user_id: int) -> str:
        return f"{ADMIN_URL_BASE}{user_id}/"

    return _get_url


@pytest.fixture
def admin_action_url() -> Callable[[int, str], str]:
    """
    Generate admin action URL for ViewSet custom actions.

    Returns:
        Callable[[int, str], str]: Function that takes user ID and action name,
        returns URL for custom action endpoint.

    Example:
        def test_password_reset(admin_client, target_user_account, admin_action_url):
            url = admin_action_url(target_user_account.id, "password")
            response = admin_client.post(url, {"new_password": "NewPass123!"})
            assert response.status_code == 200
    """

    def _get_url(user_id: int, action: str) -> str:
        return f"{ADMIN_URL_BASE}{user_id}/{action}/"

    return _get_url


@pytest.fixture
def admin_list_url() -> str:
    """
    Provide admin user list URL.

    Returns:
        str: URL for listing all users.

    Example:
        def test_user_list(admin_client, admin_list_url):
            response = admin_client.get(admin_list_url)
            assert response.status_code == 200
    """
    return ADMIN_URL_BASE


# ==================================================================================================
# FIXTURES: HELPERS
# ==================================================================================================


@pytest.fixture
def login_user(
    api_client: APIClient,
) -> Callable[[str, str], Tuple[Optional[APIClient], Dict, Optional[User]]]:
    """
    Helper fixture to perform login and return authenticated client + tokens.

    Returns:
        Callable: Function that logs in a user and returns (client, tokens, user).

    Example:
        def test_login_flow(login_user):
            client, tokens, user = login_user("username", "password")
            assert client is not None
            assert "access" in tokens
    """

    def _login(username: str, password: str) -> Tuple[Optional[APIClient], Dict, Optional[User]]:
        response = api_client.post(
            "/api/auth/login/",
            {"username": username, "password": password},
        )

        if response.status_code == 200:
            tokens = response.data
            user = User.objects.get(username=username)
            api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
            api_client.user = user  # type: ignore
            return api_client, tokens, user

        return None, response.data, None

    return _login


@pytest.fixture
def create_test_user(db) -> Callable[..., User]:
    """
    Factory fixture for creating UserAccount instances directly.

    Bypasses serializers for unit testing. Supports all User model fields.

    Returns:
        Callable: Function that creates UserAccount instances.

    Example:
        user = create_test_user(
            username="custom_user",
            email="custom@example.com",
            password="CustomPass123!",
            is_staff=True
        )

    Args:
        db: Pytest database fixture (auto-injected).

    Returns:
        User: Created user instance.
    """

    def _create_user(
        username: Optional[str] = None,
        email: Optional[str] = None,
        password: str = DEFAULT_TEST_PASSWORD,
        first_name: str = "Test",
        last_name: str = "User",
        is_staff: bool = False,
        is_active: bool = True,
    ) -> User:
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


@pytest.fixture
def get_user_by_id() -> Callable[[int], Optional[User]]:
    """
    Helper fixture to get user by ID with error handling.

    Returns:
        Callable[[int], Optional[User]]: Function that returns user or None.

    Example:
        def test_user_lookup(get_user_by_id, target_user_account):
            user = get_user_by_id(target_user_account.id)
            assert user is not None
    """

    def _get_user(user_id: int) -> Optional[User]:
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None

    return _get_user


@pytest.fixture
def valid_password_data():
    """
    Provide valid password data that meets all validation requirements.

    Returns:
        dict: Valid password payload for registration/reset endpoints.
    """
    return {
        "password": "ValidPass123!",
        "password_confirm": "ValidPass123!",
    }


@pytest.fixture
def throttle_override(mocker):
    """
    Override throttling for tests to avoid rate limiting.

    This fixture disables the default throttling behavior during tests
    by mocking the allow_request method to always return True.

    Usage:
        def test_registration(throttle_override, api_client, valid_password_data):
            # Throttling is disabled for this test
            ...
    """
    from users.throttles import RegisterRateThrottle, LoginRateThrottle

    # Mock allow_request to always return True (disable throttling)
    mocker.patch.object(RegisterRateThrottle, 'allow_request', return_value=True)
    mocker.patch.object(LoginRateThrottle, 'allow_request', return_value=True)

    yield


# ==================================================================================================
# FIXTURES: STORAGE (for admin tests)
# ==================================================================================================


@pytest.fixture
def test_file_for_users() -> SimpleUploadedFile:
    """
    Create a temporary test file for upload testing.

    Local version for users app tests (doesn't depend on storage fixtures).

    Returns:
        SimpleUploadedFile: Test file object.

    Example:
        def test_file_upload(authenticated_client, test_file_for_users):
            response = authenticated_client.post(
                "/api/storage/files/upload/",
                {"file": test_file_for_users}
            )
            assert response.status_code == 201
    """
    file_content = b"Test file content for storage application testing." * 20
    return SimpleUploadedFile(
        name="test_file.txt",
        content=file_content,
        content_type="text/plain",
    )


@pytest.fixture
def uploaded_file(db, user_account: User, test_file_for_users: SimpleUploadedFile) -> File:
    """
    Create an uploaded file in the database for testing.

    Creates file directly in DB to avoid API client state conflicts.

    Args:
        db: Pytest database fixture.
        user_account: Regular user fixture.
        test_file_for_users: Local test file fixture.

    Returns:
        File: Saved File model instance.

    Example:
        def test_admin_access_file(admin_client, uploaded_file):
            response = admin_client.get(f"/api/storage/files/{uploaded_file.id}/")
            assert response.status_code == 200
    """

    file_content = test_file_for_users.read()
    test_file_for_users.seek(0)

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
def admin_uploaded_file(db, admin_account: User, test_file_for_users: SimpleUploadedFile) -> File:
    """
    Create an uploaded file by admin user for testing.

    Creates file directly in DB to avoid API client state conflicts.

    Args:
        db: Pytest database fixture.
        admin_account: Admin user fixture.
        test_file_for_users: Local test file fixture.

    Returns:
        File: Saved File model instance owned by admin.

    Example:
        def test_admin_file_operations(admin_client, admin_uploaded_file):
            response = admin_client.delete(
                f"/api/storage/files/{admin_uploaded_file.id}/"
            )
            assert response.status_code == 204
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


@pytest.fixture
def user_with_files(
    db, create_test_user: Callable, test_file_for_users: SimpleUploadedFile
) -> Tuple[User, List[File]]:
    """
    Create a user with multiple uploaded files for storage stats testing.

    Args:
        db: Pytest database fixture.
        create_test_user: Factory fixture for creating users.
        test_file_for_users: Test file fixture.

    Returns:
        Tuple[User, List[File]]: User instance and list of their files.

    Example:
        def test_storage_stats(admin_client, user_with_files, admin_action_url):
            user, files = user_with_files
            response = admin_client.get(admin_action_url(user.id, "storage-stats"))
            assert response.status_code == 200
            assert response.data["storage"]["file_count"] == len(files)
    """

    user = create_test_user(
        username="user_with_files",
        email="files_user@example.com",
    )

    files = []
    for i in range(3):
        file_content = f"File content {i}".encode() * 100
        file_obj = File(
            owner=user,
            original_name=f"test_file_{i}.txt",
            size=len(file_content),
            comment=f"Test file {i}",
        )
        file_obj.file.save(  # pylint: disable=no-member
            f"test_file_{i}.txt",
            ContentFile(file_content),
            save=True,
        )
        files.append(file_obj)

    return user, files


# ==================================================================================================
# FIXTURES: MOCKS FOR SERVICES
# ==================================================================================================


@pytest.fixture
def mock_storage_stats(mocker) -> Callable[[Dict], Any]:
    """
    Mock the calculate_storage_stats service function.

    Useful for testing admin views without actual filesystem operations.

    Args:
        mocker: pytest-mock fixture.

    Returns:
        Callable: Function to set mock return value.

    Example:
        def test_storage_stats_endpoint(admin_client, target_user_account,
                                        admin_action_url, mock_storage_stats):
            mock_storage_stats({"file_count": 5, "total_size": 1024})
            response = admin_client.get(admin_action_url(target_user_account.id, "storage-stats"))
            assert response.data["storage"]["file_count"] == 5
    """

    def _mock(return_value: Optional[Dict] = None):
        default_stats = {"file_count": 0, "total_size": 0, "total_size_formatted": "0 B"}
        stats = return_value if return_value else default_stats

        mocker.patch(
            "users.views.admin_views.calculate_storage_stats",
            return_value=stats,
        )
        return stats

    return _mock

# ==================================================================================================
# FIXTURES: PASSWORD CHANGE TEST DATA
# ==================================================================================================

@pytest.fixture
def wrong_current_password_data():
    """
    Provide password change data with incorrect current password.

    Returns:
        dict: Payload with wrong current password.

    Example:
        def test_wrong_password(authenticated_client, wrong_current_password_data):
            response = authenticated_client.post(
                "/api/users/me/password/",
                wrong_current_password_data
            )
            assert response.status_code == 400
    """
    return {
        "current_password": "WrongPass999!",
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
def valid_password_change_data():
    """
    Provide valid password change request data.

    Returns:
        dict: Valid payload with matching passwords.
    """
    return {
        "current_password": "TestPass123!",
        "new_password": "NewSecurePass456!",
        "new_password_confirm": "NewSecurePass456!",
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
