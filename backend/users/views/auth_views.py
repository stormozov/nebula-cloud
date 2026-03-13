"""
Views for user authentication and token management.

This module provides API endpoints for:
- User registration (RegisterView)
- User login/logout (LoginView, LogoutView)
- Token refresh (CustomTokenRefreshView)

All authentication endpoints use JWT tokens for session management.
Registration and login are available to anonymous users.
Logout and token refresh require authentication.

Endpoints:
    POST /api/users/auth/register/  - Register new user
    POST /api/users/auth/login/     - Login and get tokens
    POST /api/users/auth/logout/    - Logout and blacklist token
    POST /api/users/auth/refresh/   - Refresh access token
"""

from typing import Any

from rest_framework import generics, permissions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView

from core.utils import get_client_ip
from users.loggers import auth_logger
from users.serializers import (
    TokenResponseSerializer,
    UserLoginSerializer,
    UserRegistrationSerializer,
)
from users.services import AuthResponseBuilder
from users.throttles import LoginRateThrottle, RegisterRateThrottle

# ==================================================================================================
# USER REGISTRATION
# ==================================================================================================


class RegisterView(generics.CreateAPIView):
    """
    API endpoint for user registration.

    Creates a new user account with validation of:
    - Username (Latin letters and numbers, 4-20 chars, starts with letter)
    - Email (valid email format)
    - Password (min 6 chars, uppercase, digit, special character)

    On success, returns user data with JWT tokens (access + refresh).
    No authentication required for this endpoint.

    Attributes:
        serializer_class: UserRegistrationSerializer for input validation.
        permission_classes: AllowAny - registration is open to all users.
        throttle_classes: RegisterRateThrottle - prevents abuse.

    Endpoint:
        POST /api/users/auth/register/

    Request Body:
        {
            "username": "string (4-20 chars)",
            "email": "valid@email.com",
            "password": "SecurePass123!",
            "first_name": "string (optional)",
            "last_name": "string (optional)"
        }

    Response (201 Created):
        {
            "user": { "id": 1, "username": "...", "email": "..." },
            "access": "jwt_token",
            "refresh": "jwt_token"
        }

    Logs:
        Info: Successful registration with user details and IP.
        Error: Registration failures with error details.
    """

    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]
    throttle_classes = [RegisterRateThrottle]

    def create(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Handle user registration request.

        Validates input data, creates user account, generates JWT tokens,
        and returns authentication response.

        Args:
            request: The HTTP request object containing registration data.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: 201 Created with user data and tokens on success.
            Response: 400 Bad Request with validation errors on failure.

        Raises:
            ValidationError: If input data fails serializer validation.
        """

        # 1. Validate registration data via serializer
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # 2. Create new user account
        new_user = serializer.save()

        # 3. Generate JWT refresh token
        refresh = RefreshToken.for_user(new_user)

        # 4. Build response data with tokens
        prepared_data = AuthResponseBuilder(new_user).with_tokens(refresh).build()

        # 5. Serialize response
        response_serializer = TokenResponseSerializer(prepared_data)

        # 6. Log successful registration
        auth_logger.info(
            "User registered successfully: email=%s, username=%s, IP=%s, response=%s",
            new_user.email,
            new_user.username,
            get_client_ip(request),
            response_serializer.data,
        )

        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    def handle_exception(self, exc: Exception) -> Response:
        """
        Handle exceptions during registration and log errors.

        Overrides default exception handling to add logging for
        registration failures.

        Args:
            exc: The exception that was raised.

        Returns:
            Response: Formatted error response with appropriate status code.
        """
        auth_logger.error(
            "Registration failed: %s, IP=%s",
            str(exc),
            get_client_ip(self.request),
        )
        return super().handle_exception(exc)


# ==================================================================================================
# USER LOGIN
# ==================================================================================================


class LoginView(APIView):
    """
    API endpoint for user authentication (login).

    Authenticates user with username/email and password.
    On success, returns user data with JWT tokens (access + refresh).
    No authentication required for this endpoint.

    Attributes:
        serializer_class: UserLoginSerializer for credential validation.
        permission_classes: AllowAny - login is open to all users.
        throttle_classes: LoginRateThrottle - prevents brute force attacks.

    Endpoint:
        POST /api/users/auth/login/

    Request Body:
        {
            "username": "string",
            "password": "string"
        }

    Response (200 OK):
        {
            "user": { "id": 1, "username": "...", "email": "..." },
            "access": "jwt_token",
            "refresh": "jwt_token"
        }

    Response (400 Bad Request):
        {
            "detail": "Invalid credentials"
        }

    Logs:
        Info: Successful login with user details and IP.
        Warning: Failed login attempts with email and errors.
    """

    serializer_class = UserLoginSerializer
    permission_classes = [permissions.AllowAny]
    throttle_classes = [LoginRateThrottle]

    def post(self, request: Request) -> Response:
        """
        Handle user login request.

        Validates credentials, authenticates user, generates JWT tokens,
        and returns authentication response.

        Args:
            request: The HTTP request object containing login credentials.

        Returns:
            Response: 200 OK with user data and tokens on success.
            Response: 400 Bad Request with error message on failure.
        """

        # 1. Validate login credentials via serializer
        serializer = UserLoginSerializer(data=request.data)

        if not serializer.is_valid():
            auth_logger.warning(
                "Failed login attempt: email=%s, errors=%s, IP=%s",
                request.data.get("email", "unknown"),
                serializer.errors,
                get_client_ip(request),
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # 2. Get authenticated user from serializer
        user = serializer.validated_data["user"]

        # 3. Generate JWT refresh token
        refresh = RefreshToken.for_user(user)

        # 4. Build response data with tokens
        prepared_data = AuthResponseBuilder(user).with_tokens(refresh).build()

        # 5. Serialize response
        response_serializer = TokenResponseSerializer(prepared_data)

        # 6. Log successful login
        auth_logger.info(
            "User logged in successfully: email=%s, username=%s, IP=%s, response=%s",
            user.email,
            user.username,
            get_client_ip(request),
            response_serializer.data,
        )

        return Response(response_serializer.data, status=status.HTTP_200_OK)


# ==================================================================================================
# USER LOGOUT
# ==================================================================================================


class LogoutView(APIView):
    """
    API endpoint for user logout.

    Blacklists the provided refresh token to prevent further use.
    Requires authentication (valid access token in Authorization header).

    Attributes:
        permission_classes: IsAuthenticated - logout requires valid session.

    Endpoint:
        POST /api/users/auth/logout/

    Request Body:
        {
            "refresh": "jwt_refresh_token"
        }

    Response (200 OK):
        {
            "detail": "Successfully logged out."
        }

    Response (400 Bad Request):
        {
            "detail": "Refresh token is required."
        }

    Logs:
        Info: Successful logout with user details and IP.
        Warning: Missing refresh token attempts.
        Error: Invalid token or other failures.
    """

    serializer_class = None
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        """
        Handle user logout request.

        Blacklists the provided refresh token to invalidate the session.
        The access token remains valid until expiration (short-lived).

        Args:
            request: The HTTP request object containing refresh token.

        Returns:
            Response: 200 OK with success message on successful logout.
            Response: 400 Bad Request if token is missing or invalid.

        Raises:
            TokenError: If refresh token is invalid or already blacklisted.
        """
        try:
            # 1. Get user email for logging
            user_email = request.user.email

            # 2. Get refresh token from request body
            refresh_token = request.data.get("refresh")

            # 3. Validate refresh token presence
            if not refresh_token:
                auth_logger.warning(
                    "Logout failed: missing refresh token, user=%s, IP=%s",
                    user_email,
                    get_client_ip(request),
                )
                return Response(
                    {"detail": "Refresh token is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # 4. Blacklist refresh token
            token = RefreshToken(refresh_token)
            token.blacklist()

            # 5. Log successful logout
            auth_logger.info(
                "User logged out successfully: email=%s, username=%s, IP=%s",
                user_email,
                request.user.username,
                get_client_ip(request),
            )

            return Response(
                {"detail": "Successfully logged out."},
                status=status.HTTP_200_OK,
            )
        except TokenError as e:
            auth_logger.error(
                "Logout failed - invalid token: %s, user=%s, IP=%s",
                str(e),
                user_email,
                get_client_ip(request),
            )
            return Response(
                {"detail": f"Invalid token: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            auth_logger.error(
                "Logout failed: %s, user=%s, IP=%s",
                str(e),
                user_email,
                get_client_ip(request),
            )
            return Response(
                {"detail": f"Logout failed: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )


# ==================================================================================================
# TOKEN REFRESH
# ==================================================================================================


class CustomTokenRefreshView(TokenRefreshView):
    """
    API endpoint for refreshing access token.

    Returns a new access token using a valid refresh token.
    The refresh token must not be expired or blacklisted.
    No authentication required (uses refresh token from request body).

    Attributes:
        permission_classes: AllowAny - token refresh doesn't require session.

    Endpoint:
        POST /api/users/auth/refresh/

    Request Body:
        {
            "refresh": "jwt_refresh_token"
        }

    Response (200 OK):
        {
            "access": "new_jwt_access_token"
        }

    Response (401 Unauthorized):
        {
            "detail": "Token is invalid or expired"
        }

    Notes:
        - Access tokens are short-lived (configurable, default 5 minutes)
        - Refresh tokens are long-lived (configurable, default 7 days)
        - Refresh tokens can be blacklisted on logout for security

    Logs:
        Handled by DRF SimpleJWT default logging.
        Custom logging can be added via token validation overrides.
    """

    serializer_class = None
    permission_classes = [permissions.AllowAny]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Handle token refresh request.

        Validates refresh token and returns new access token.
        Extends default TokenRefreshView with custom logging.

        Args:
            request: The HTTP request object containing refresh token.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: 200 OK with new access token on success.
            Response: 401 Unauthorized if token is invalid/expired.
        """

        # Log refresh attempt (before calling parent)
        auth_logger.debug(
            "Token refresh attempt: IP=%s",
            get_client_ip(request),
        )

        # Call parent implementation
        response = super().post(request, *args, **kwargs)

        # Log result
        if response.status_code == status.HTTP_200_OK:
            auth_logger.debug(
                "Token refresh successful: IP=%s",
                get_client_ip(request),
            )
        else:
            auth_logger.warning(
                "Token refresh failed: status=%d, IP=%s",
                response.status_code,
                get_client_ip(request),
            )

        return response
