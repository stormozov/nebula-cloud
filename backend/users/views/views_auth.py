"""
Views for user authentication.

This module provides API endpoints for:
- User registration (RegisterView)
- User login/logout (LoginView, LogoutView)
- Token refresh (CustomTokenRefreshView)
"""

from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView

from users.serializers import (
    TokenResponseSerializer,
    UserLoginSerializer,
    UserRegistrationSerializer,
)
from users.services import AuthResponseBuilder
from users.throttles import LoginRateThrottle, RegisterRateThrottle
from utils.ip_utils import get_client_ip

from ..loggers import auth_logger

# ==============================================================================
# AUTHENTICATION
# ==============================================================================


class RegisterView(generics.CreateAPIView):
    """
    API endpoint for user registration.

    `POST /api/auth/register/`
    Creates a new user account and returns JWT tokens.
    """

    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]
    throttle_classes = [RegisterRateThrottle]

    def create(self, request, *args, **kwargs) -> Response:
        """Handle user registration."""

        # 1. Validate data via serializer
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # 2. Create new user
        new_user = serializer.save()

        # 3. Generate refresh token
        refresh = RefreshToken.for_user(new_user)

        # 4. Prepare response data
        prepared_data = AuthResponseBuilder(new_user).with_tokens(refresh).build()

        # 5. Serialize response
        response_serializer = TokenResponseSerializer(prepared_data)

        # 6. Return response with user details
        auth_logger.info(
            "User registered successfully: email=%s, username=%s, IP=%s",
            new_user.email,
            new_user.username,
            get_client_ip(request),
        )

        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    def handle_exception(self, exc):
        """Handle exceptions and log them."""
        auth_logger.error(
            "Registration failed: %s, IP=%s",
            str(exc),
            get_client_ip(self.request),
        )
        return super().handle_exception(exc)


class LoginView(APIView):
    """
    API endpoint for user login.

    `POST /api/auth/login/`
    Authenticates user and returns JWT tokens.
    """

    serializer_class = UserLoginSerializer
    permission_classes = [permissions.AllowAny]
    throttle_classes = [LoginRateThrottle]

    def post(self, request) -> Response:
        """Handle user login."""

        serializer = UserLoginSerializer(data=request.data)

        # 1. Validate data via serializer
        if not serializer.is_valid():
            auth_logger.warning(
                "Failed login attempt: email=%s, errors=%s, IP=%s",
                request.data.get("email", "unknown"),
                serializer.errors,
                get_client_ip(request),
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # 2. Get user
        user = serializer.validated_data["user"]

        # 3. Generate refresh token
        refresh = RefreshToken.for_user(user)

        # 4. Prepare response data
        prepared_data = AuthResponseBuilder(user).with_tokens(refresh).build()

        # 5. Serialize response
        response_serializer = TokenResponseSerializer(prepared_data)

        # 6. Return response with user details
        auth_logger.info(
            "User logged in successfully: email=%s, username=%s, IP=%s",
            user.email,
            user.username,
            get_client_ip(request),
        )

        return Response(response_serializer.data, status=status.HTTP_200_OK)


class LogoutView(APIView):
    """
    API endpoint for user logout.

    `POST /api/auth/logout/`
    Blacklists the refresh token to prevent further use.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request) -> Response:
        """
        Handle user logout.

        Blacklists the provided refresh token.
        """
        try:
            # 1. Get user data
            refresh_token = request.data.get("refresh")
            user_email = request.user.email

            # 2. Validate refresh token
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

            # 3. Blacklist refresh token
            token = RefreshToken(refresh_token)
            token.blacklist()

            # 4. Return success response with message
            auth_logger.info(
                "User logged out successfully: email=%s, username=%s, IP=%s",
                user_email,
                request.user.username,
                get_client_ip(request),
            )

            return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
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


# ==============================================================================
# TOKEN REFRESH
# ==============================================================================


class CustomTokenRefreshView(TokenRefreshView):
    """
    API endpoint for refreshing access token.

    `POST /api/auth/refresh/`
    Returns a new access token using a valid refresh token.
    """
