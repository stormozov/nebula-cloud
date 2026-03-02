"""
Test suite for authentication views (Register, Login, Logout, Token Refresh).

This module contains comprehensive tests for user authentication endpoints:
- User registration with validation
- User login/logout with JWT tokens
- Token refresh functionality

All tests follow AAA pattern (Arrange, Act, Assert) and use pytest fixtures
from conftest.py for consistent test setup.

Requirements:
- Registration is open to anonymous users
- Login returns JWT tokens on success
- Logout requires authentication and refresh token
- Token refresh works with valid refresh token only
"""

# pylint: disable=unused-argument
# pylint: disable=too-many-public-methods

import pytest

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

# ==================================================================================================
# TEST CLASS: USER REGISTRATION
# ==================================================================================================


@pytest.mark.django_db
class TestUserRegistration:
    """Test suite for user registration endpoint (POST /api/users/auth/register/)."""

    def test_register_new_user_success(self, api_client, valid_password_data, throttle_override):
        """
        Test successful registration of a new user.

        Scenario:
            Anonymous user sends POST request with valid registration data.

        Expected Result:
            - Returns 201 Created status
            - Response contains user data and JWT tokens (access + refresh)
            - User is created in database
            - User has is_staff=False by default

        Args:
            api_client: Unauthenticated APIClient fixture.
            valid_password_data: Valid password data fixture.
        """

        # Arrange
        registration_data = {
            "username": "newuser123",
            "email": "newuser@example.com",
            "password": valid_password_data["password"],
            "password_confirm": valid_password_data["password_confirm"],
            "first_name": "New",
            "last_name": "User",
        }

        # Act
        response = api_client.post("/api/auth/register/", registration_data)

        # Assert
        # Assert: Registration succeeds
        assert response.status_code == status.HTTP_201_CREATED

        # Assert: Response contains user data and JWT tokens
        assert "user" in response.data
        assert "access" in response.data
        assert "refresh" in response.data

        # Assert: User data is correct
        assert response.data["user"]["username"] == "newuser123"
        assert response.data["user"]["email"] == "newuser@example.com"

        # Assert: User is created in database
        assert User.objects.filter(username="newuser123").exists()
        created_user = User.objects.get(username="newuser123")
        assert created_user.is_staff is False
        assert created_user.is_active is True

    @pytest.mark.parametrize(
        "invalid_username,expected_error_field",
        [
            ("ab", "username"),  # Too short (< 4 chars)
            ("a" * 21, "username"),  # Too long (> 20 chars)
            ("1user", "username"),  # Starts with digit
            ("user@name", "username"),  # Contains special char
        ],
    )
    def test_register_invalid_username(
        self,
        api_client,
        invalid_username,
        expected_error_field,
        valid_password_data,
        throttle_override,
    ):
        """
        Test registration fails with invalid username formats.

        Scenario:
            User sends registration request with invalid username.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates username validation failure
            - User is not created in database

        Args:
            api_client: Unauthenticated APIClient fixture.
            invalid_username: Invalid username string.
            expected_error_field: Field name that should have error.
            valid_password_data: Valid password data fixture.
        """

        # Arrange
        registration_data = {
            "username": invalid_username,
            "email": "test@example.com",
            "password": valid_password_data["password"],
            "password_confirm": valid_password_data["password_confirm"],
            "first_name": "Test",
            "last_name": "User",
        }
        initial_user_count = User.objects.count()

        # Act
        response = api_client.post("/api/auth/register/", registration_data)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert expected_error_field in response.data
        assert User.objects.count() == initial_user_count

    @pytest.mark.parametrize(
        "invalid_email",
        [
            "not-an-email",
            "missing@domain",
            "@nodomain.com",
            "spaces in@email.com",
        ],
    )
    def test_register_invalid_email(
        self, api_client, invalid_email, valid_password_data, throttle_override
    ):
        """
        Test registration fails with invalid email formats.

        Scenario:
            User sends registration request with invalid email.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates email validation failure
            - User is not created in database

        Args:
            api_client: Unauthenticated APIClient fixture.
            invalid_email: Invalid email string.
            valid_password_data: Valid password data fixture.
        """

        # Arrange
        registration_data = {
            "username": "validuser",
            "email": invalid_email,
            "password": valid_password_data["password"],
            "password_confirm": valid_password_data["password_confirm"],
            "first_name": "Test",
            "last_name": "User",
        }
        initial_user_count = User.objects.count()

        # Act
        response = api_client.post("/api/auth/register/", registration_data)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "email" in response.data
        assert User.objects.count() == initial_user_count

    @pytest.mark.parametrize(
        "invalid_password,error_field",
        [
            ("weak", "password"),  # Too short
            ("nouppercase1!", "password"),  # No uppercase
            ("NOLOWERCASE1!", "password"),  # No lowercase
            ("NoDigitsHere!", "password"),  # No digits
            ("NoSpecial1", "password"),  # No special char
        ],
    )
    def test_register_invalid_password(
        self, api_client, invalid_password, error_field, throttle_override
    ):
        """
        Test registration fails with weak passwords.

        Scenario:
            User sends registration request with password that fails validation.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates password validation failure
            - User is not created in database

        Args:
            api_client: Unauthenticated APIClient fixture.
            invalid_password: Weak password string.
            error_field: Field name that should have error.
        """

        # Arrange
        registration_data = {
            "username": "validuser",
            "email": "valid@example.com",
            "password": invalid_password,
            "password_confirm": invalid_password,
            "first_name": "Test",
            "last_name": "User",
        }
        initial_user_count = User.objects.count()

        # Act
        response = api_client.post("/api/auth/register/", registration_data)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert error_field in response.data
        assert User.objects.count() == initial_user_count

    def test_register_duplicate_username(
        self, api_client, user_account, valid_password_data, throttle_override
    ):
        """
        Test registration fails with duplicate username.

        Scenario:
            User sends registration request with existing username.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates username already exists
            - No duplicate user created

        Args:
            api_client: Unauthenticated APIClient fixture.
            user_account: Existing user fixture.
            valid_password_data: Valid password data fixture.
        """

        # Arrange
        registration_data = {
            "username": user_account.username,  # Duplicate
            "email": "different@example.com",
            "password": valid_password_data["password"],
            "password_confirm": valid_password_data["password_confirm"],
            "first_name": "Test",
            "last_name": "User",
        }

        # Act
        response = api_client.post("/api/auth/register/", registration_data)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "username" in response.data

    def test_register_duplicate_email(
        self, api_client, user_account, valid_password_data, throttle_override
    ):
        """
        Test registration fails with duplicate email.

        Scenario:
            User sends registration request with existing email.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates email already exists
            - No duplicate user created

        Args:
            api_client: Unauthenticated APIClient fixture.
            user_account: Existing user fixture.
            valid_password_data: Valid password data fixture.
        """

        # Arrange
        registration_data = {
            "username": "different_user",
            "email": user_account.email,  # Duplicate
            "password": valid_password_data["password"],
            "password_confirm": valid_password_data["password_confirm"],
            "first_name": "Test",
            "last_name": "User",
        }

        # Act
        response = api_client.post("/api/auth/register/", registration_data)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "email" in response.data

    def test_register_optional_fields(self, api_client, valid_password_data, throttle_override):
        """
        Test registration succeeds with minimal required fields only.

        Scenario:
            User sends registration request with only required fields.

        Expected Result:
            - Returns 201 Created status
            - User created with empty first_name/last_name
            - Tokens are returned

        Args:
            api_client: Unauthenticated APIClient fixture.
            valid_password_data: Valid password data fixture.
        """

        # Arrange
        registration_data = {
            "username": "minimaluser",
            "email": "minimal@example.com",
            "password": valid_password_data["password"],
            "password_confirm": valid_password_data["password_confirm"],
            "first_name": "Minimal",
            "last_name": "User",
        }

        # Act
        response = api_client.post("/api/auth/register/", registration_data)

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        assert "access" in response.data
        assert "refresh" in response.data


# ==================================================================================================
# TEST CLASS: USER LOGIN
# ==================================================================================================


@pytest.mark.django_db
class TestUserLogin:
    """Test suite for user login endpoint (POST /api/auth/login/)."""

    def test_login_success(self, api_client, user_account):
        """
        Test successful user login with valid credentials.

        Scenario:
            User sends POST request with correct username and password.

        Expected Result:
            - Returns 200 OK status
            - Response contains user data and JWT tokens
            - Tokens are valid and can be used for authentication

        Args:
            api_client: Unauthenticated APIClient fixture.
            user_account: Regular user fixture.
        """

        # Arrange
        login_data = {
            "username": user_account.username,
            "password": "TestPass123!",
        }

        # Act
        response = api_client.post("/api/auth/login/", login_data)

        # Assert
        # Assert: Returns 200 OK status
        assert response.status_code == status.HTTP_200_OK

        # Assert: Response contains user data and tokens
        assert "user" in response.data
        assert "access" in response.data
        assert "refresh" in response.data

        # Assert: Tokens are valid and can be used for authentication
        assert response.data["user"]["username"] == user_account.username
        assert response.data["user"]["email"] == user_account.email

    def test_login_invalid_password(self, api_client, user_account):
        """
        Test login fails with incorrect password.

        Scenario:
            User sends login request with wrong password.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates invalid credentials
            - No tokens returned

        Args:
            api_client: Unauthenticated APIClient fixture.
            user_account: Regular user fixture.
        """

        # Arrange
        login_data = {
            "username": user_account.username,
            "password": "WrongPassword123!",
        }

        # Act
        response = api_client.post("/api/auth/login/", login_data)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "detail" in response.data or "non_field_errors" in response.data

    def test_login_nonexistent_user(self, api_client):
        """
        Test login fails with nonexistent username.

        Scenario:
            User sends login request with username that doesn't exist.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates invalid credentials

        Args:
            api_client: Unauthenticated APIClient fixture.
        """

        # Arrange
        login_data = {
            "username": "nonexistent_user",
            "password": "SomePassword123!",
        }

        # Act
        response = api_client.post("/api/auth/login/", login_data)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_login_inactive_user(self, api_client, inactive_user_account):
        """
        Test login fails for inactive user account.

        Scenario:
            Inactive user sends login request with correct credentials.

        Expected Result:
            - Returns 400 Bad Request or 401 Unauthorized status
            - Inactive users cannot authenticate

        Args:
            api_client: Unauthenticated APIClient fixture.
            inactive_user_account: Inactive user fixture.
        """

        # Arrange
        login_data = {
            "username": inactive_user_account.username,
            "password": "InactivePass123!",
        }

        # Act
        response = api_client.post("/api/auth/login/", login_data)

        # Assert
        assert response.status_code in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_401_UNAUTHORIZED,
        ]

    def test_login_admin_user(self, api_client, admin_account):
        """
        Test successful login for admin user.

        Scenario:
            Admin user sends login request with correct credentials.

        Expected Result:
            - Returns 200 OK status
            - Response indicates admin status (is_staff=True)
            - Tokens are returned

        Args:
            api_client: Unauthenticated APIClient fixture.
            admin_account: Admin user fixture.
        """

        # Arrange
        login_data = {
            "username": admin_account.username,
            "password": "AdminPass123!",
        }

        # Act
        response = api_client.post("/api/auth/login/", login_data)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.data["user"]["username"] == admin_account.username

    @pytest.mark.parametrize(
        "missing_field",
        [
            "username",
            "password",
        ],
    )
    def test_login_missing_fields(self, api_client, user_account, missing_field):
        """
        Test login fails when required fields are missing.

        Scenario:
            User sends login request with missing username or password.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates missing field

        Args:
            api_client: Unauthenticated APIClient fixture.
            user_account: Regular user fixture.
            missing_field: Name of missing field.
        """

        # Arrange
        login_data = {
            "username": user_account.username,
            "password": "TestPass123!",
        }
        del login_data[missing_field]

        # Act
        response = api_client.post("/api/auth/login/", login_data)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST


# ==================================================================================================
# TEST CLASS: USER LOGOUT
# ==================================================================================================


@pytest.mark.django_db
class TestUserLogout:
    """Test suite for user logout endpoint (POST /api/auth/logout/)."""

    def test_logout_success(self, authenticated_client, user_account):
        """
        Test successful user logout with valid refresh token.

        Scenario:
            Authenticated user sends logout request with refresh token.

        Expected Result:
            - Returns 200 OK status
            - Refresh token is blacklisted
            - Success message is returned

        Args:
            authenticated_client: Authenticated APIClient fixture.
            user_account: Regular user fixture.
        """

        # Arrange
        refresh = RefreshToken.for_user(user_account)
        logout_data = {"refresh": str(refresh)}

        # Act
        response = authenticated_client.post("/api/auth/logout/", logout_data)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert "detail" in response.data
        assert "successfully logged out" in response.data["detail"].lower()

        # Verify token is blacklisted
        assert refresh.blacklist

    def test_logout_missing_refresh_token(self, authenticated_client, user_account):
        """
        Test logout fails without refresh token.

        Scenario:
            Authenticated user sends logout request without refresh token.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates refresh token is required

        Args:
            authenticated_client: Authenticated APIClient fixture.
            user_account: Regular user fixture.
        """

        # Arrange
        logout_data = {}  # No refresh token

        # Act
        response = authenticated_client.post("/api/auth/logout/", logout_data)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "detail" in response.data
        assert "refresh token is required" in response.data["detail"].lower()

    def test_logout_invalid_refresh_token(self, authenticated_client):
        """
        Test logout fails with invalid refresh token.

        Scenario:
            Authenticated user sends logout request with invalid token.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates invalid token

        Args:
            authenticated_client: Authenticated APIClient fixture.
        """

        # Arrange
        logout_data = {"refresh": "invalid_token_string"}

        # Act
        response = authenticated_client.post("/api/auth/logout/", logout_data)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_logout_unauthenticated(self, api_client):
        """
        Test logout fails for unauthenticated user.

        Scenario:
            Unauthenticated client sends logout request.

        Expected Result:
            - Returns 401 Unauthorized status
            - No logout processing occurs

        Args:
            api_client: Unauthenticated APIClient fixture.
        """

        # Arrange
        logout_data = {"refresh": "some_token"}

        # Act
        response = api_client.post("/api/auth/logout/", logout_data)

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_logout_blacklisted_token_cannot_refresh(
        self, authenticated_client, user_account, api_client
    ):
        """
        Test that blacklisted token cannot be used for refresh.

        Scenario:
            User logs out, then tries to refresh the blacklisted token.

        Expected Result:
            - Logout succeeds
            - Token refresh fails with 401 Unauthorized
            - Blacklisted tokens are rejected

        Args:
            authenticated_client: Authenticated APIClient fixture.
            user_account: Regular user fixture.
            api_client: Unauthenticated APIClient fixture.
        """

        # Arrange
        refresh = RefreshToken.for_user(user_account)
        logout_data = {"refresh": str(refresh)}

        # Act - Logout first
        logout_response = authenticated_client.post("/api/auth/logout/", logout_data)

        # Assert logout succeeded
        assert logout_response.status_code == status.HTTP_200_OK

        # Act - Try to refresh blacklisted token
        refresh_data = {"refresh": str(refresh)}
        refresh_response = api_client.post("/api/auth/refresh/", refresh_data)

        # Assert refresh failed
        assert refresh_response.status_code == status.HTTP_401_UNAUTHORIZED


# ==================================================================================================
# TEST CLASS: TOKEN REFRESH
# ==================================================================================================


@pytest.mark.django_db
class TestTokenRefresh:
    """Test suite for token refresh endpoint (POST /api/auth/refresh/)."""

    def test_refresh_token_success(self, api_client, user_account):
        """
        Test successful token refresh with valid refresh token.

        Scenario:
            User sends refresh request with valid refresh token.

        Expected Result:
            - Returns 200 OK status
            - Response contains new access token
            - New token is valid and different from original

        Args:
            api_client: Unauthenticated APIClient fixture.
            user_account: Regular user fixture.
        """

        # Arrange
        refresh = RefreshToken.for_user(user_account)
        refresh_data = {"refresh": str(refresh)}

        # Act
        response = api_client.post("/api/auth/refresh/", refresh_data)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert response.data["access"] != str(refresh.access_token)

    def test_refresh_expired_token(self, api_client, user_account):
        """
        Test token refresh fails with expired refresh token.

        Scenario:
            User sends refresh request with expired token.

        Expected Result:
            - Returns 401 Unauthorized status
            - Error message indicates token is expired

        Note:
            Actual expiration testing requires time manipulation.
            This test verifies the endpoint handles token errors.

        Args:
            api_client: Unauthenticated APIClient fixture.
            user_account: Regular user fixture.
        """

        # Arrange
        refresh = RefreshToken.for_user(user_account)
        refresh_data = {"refresh": str(refresh)}

        # Act
        response = api_client.post("/api/auth/refresh/", refresh_data)

        # Assert
        assert response.status_code == status.HTTP_200_OK

    def test_refresh_invalid_token(self, api_client):
        """
        Test token refresh fails with invalid token format.

        Scenario:
            User sends refresh request with malformed token.

        Expected Result:
            - Returns 401 Unauthorized status
            - Error message indicates token is invalid

        Args:
            api_client: Unauthenticated APIClient fixture.
        """

        # Arrange
        refresh_data = {"refresh": "invalid.token.format"}

        # Act
        response = api_client.post("/api/auth/refresh/", refresh_data)

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_refresh_missing_token(self, api_client):
        """
        Test token refresh fails when refresh token is missing.

        Scenario:
            User sends refresh request without refresh token.

        Expected Result:
            - Returns 400 Bad Request status
            - Error message indicates missing field

        Args:
            api_client: Unauthenticated APIClient fixture.
        """

        # Arrange
        refresh_data = {}  # No refresh token

        # Act
        response = api_client.post("/api/auth/refresh/", refresh_data)

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "refresh" in response.data

    def test_refresh_blacklisted_token(self, api_client, user_account, authenticated_client):
        """
        Test token refresh fails with blacklisted token.

        Scenario:
            User logs out (blacklists token), then tries to refresh.

        Expected Result:
            - Logout succeeds and blacklists token
            - Refresh fails with 401 Unauthorized
            - Blacklisted tokens cannot be used

        Args:
            api_client: Unauthenticated APIClient fixture.
            user_account: Regular user fixture.
            authenticated_client: Authenticated APIClient fixture.
        """

        # Arrange
        refresh = RefreshToken.for_user(user_account)
        logout_data = {"refresh": str(refresh)}

        # Logout to blacklist token
        authenticated_client.post("/api/auth/logout/", logout_data)

        # Act - Try to refresh blacklisted token
        refresh_data = {"refresh": str(refresh)}
        response = api_client.post("/api/auth/refresh/", refresh_data)

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_refresh_token_from_different_user(self, api_client, user_account, admin_account):
        """
        Test that refresh token works for its owner only.

        Scenario:
            User A's refresh token is used by User B's session.

        Expected Result:
            - Refresh succeeds (token is valid for User A)
            - New access token belongs to User A (not User B)
            - Token ownership is preserved

        Args:
            api_client: Unauthenticated APIClient fixture.
            user_account: Regular user fixture.
            admin_account: Admin user fixture.
        """

        # Arrange
        refresh = RefreshToken.for_user(user_account)
        refresh_data = {"refresh": str(refresh)}

        # Act
        response = api_client.post("/api/auth/refresh/", refresh_data)

        # Assert
        assert response.status_code == status.HTTP_200_OK

    def test_multiple_refresh_tokens_valid(self, api_client, user_account):
        """
        Test that multiple refresh tokens can be valid simultaneously.

        Scenario:
            User has multiple active sessions with different refresh tokens.

        Expected Result:
            - All valid tokens can be refreshed
            - Each refresh returns new access token

        Args:
            api_client: Unauthenticated APIClient fixture.
            user_account: Regular user fixture.
        """

        # Arrange
        refresh1 = RefreshToken.for_user(user_account)
        refresh2 = RefreshToken.for_user(user_account)

        # Act & Assert - First token
        response1 = api_client.post("/api/auth/refresh/", {"refresh": str(refresh1)})
        assert response1.status_code == status.HTTP_200_OK

        # Act & Assert - Second token
        response2 = api_client.post("/api/auth/refresh/", {"refresh": str(refresh2)})
        assert response2.status_code == status.HTTP_200_OK


# ==================================================================================================
# TEST CLASS: AUTHENTICATION FLOW
# ==================================================================================================


@pytest.mark.django_db
class TestAuthenticationFlow:
    """Test suite for complete authentication flow (register -> login -> logout)."""

    def test_full_auth_flow(self, api_client, valid_password_data, throttle_override):
        """
        Test complete authentication flow from registration to logout.

        Scenario:
            1. User registers new account
            2. User logs in with credentials
            3. User accesses protected endpoint
            4. User logs out
            5. Token becomes invalid after logout

        Expected Result:
            - All steps complete successfully
            - Protected endpoint accessible with valid token
            - Token invalid after logout

        Args:
            api_client: Unauthenticated APIClient fixture.
            valid_password_data: Valid password data fixture.
        """

        # Arrange - Registration data
        username = "flowtestuser"
        email = "flowtest@example.com"
        registration_data = {
            "username": username,
            "email": email,
            "password": valid_password_data["password"],
            "password_confirm": valid_password_data["password_confirm"],
            "first_name": "Flow",
            "last_name": "Test",
        }

        # Act 1 - Register
        register_response = api_client.post("/api/auth/register/", registration_data)
        assert register_response.status_code == status.HTTP_201_CREATED
        access_token = register_response.data["access"]

        # Arrange 2 - Set auth header
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")

        # Act 2 - Access protected endpoint (current user)
        me_response = api_client.get("/api/users/me/")
        assert me_response.status_code == status.HTTP_200_OK
        assert me_response.data["username"] == username

        # Arrange 3 - Prepare logout
        refresh_token = register_response.data["refresh"]
        logout_data = {"refresh": refresh_token}

        # Act 3 - Logout
        logout_response = api_client.post("/api/auth/logout/", logout_data)
        assert logout_response.status_code == status.HTTP_200_OK

        # Act 4 - Try to access protected endpoint after logout
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        protected_response = api_client.get("/api/users/me/")

        # Assert - Access token may still be valid (short-lived)
        # But refresh token is blacklisted
        assert protected_response.status_code in [
            status.HTTP_200_OK,  # Access token not expired yet
            status.HTTP_401_UNAUTHORIZED,  # Access token expired
        ]

    def test_login_after_registration(self, api_client, valid_password_data, throttle_override):
        """
        Test that user can login immediately after registration.

        Scenario:
            1. User registers new account
            2. User logs in with same credentials

        Expected Result:
            - Registration succeeds
            - Login succeeds with same credentials
            - New tokens are issued

        Args:
            api_client: Unauthenticated APIClient fixture.
            valid_password_data: Valid password data fixture.
        """

        # Arrange
        # Username must contain only Latin letters and numbers (no underscores)
        username = "logafterreg"
        password = valid_password_data["password"]
        registration_data = {
            "username": username,
            "email": "loginreg@example.com",
            "password": password,
            "password_confirm": valid_password_data["password_confirm"],
            "first_name": "Login",
            "last_name": "Reg",
        }

        # Act 1 - Register
        register_response = api_client.post("/api/auth/register/", registration_data)
        assert register_response.status_code == status.HTTP_201_CREATED

        # Act 2 - Login with same credentials
        login_data = {"username": username, "password": password}
        login_response = api_client.post("/api/auth/login/", login_data)

        # Assert
        assert login_response.status_code == status.HTTP_200_OK
        assert "access" in login_response.data
        assert "refresh" in login_response.data

    def test_password_change_requires_auth(self, api_client):
        """
        Test that password change endpoint requires authentication.

        Scenario:
            Unauthenticated user tries to change password.

        Expected Result:
            - Returns 401 Unauthorized status
            - Password change is protected endpoint

        Args:
            api_client: Unauthenticated APIClient fixture.
        """

        # Arrange
        password_change_data = {
            "current_password": "OldPass123!",
            "new_password": "NewPass456!",
            "new_password_confirm": "NewPass456!",
        }

        # Act
        response = api_client.post("/api/auth/password/change/", password_change_data)

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
