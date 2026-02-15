"""
Views for user authentication and management.

This module provides API endpoints for:
- User registration
- User login/logout
- Current user profile management
"""

from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView

from users.models import UserAccount
from users.serializers import (
    TokenResponseSerializer,
    UserLoginSerializer,
    UserRegistrationSerializer,
    UserSerializer,
)
from users.throttles import LoginRateThrottle, RegisterRateThrottle

from .logging import auth_logger, logger
from .utils import get_client_ip

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
        """
        Handle user registration.

        Returns:
            Response: JWT tokens and user data on success.
        """

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Create user
        user = serializer.save()

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)

        # Prepare response data
        token_data = {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": user,
        }

        # Serialize response
        response_serializer = TokenResponseSerializer(token_data)

        # Log successful registration
        auth_logger.info(
            "User registered successfully: email=%s, username=%s, IP=%s",
            user.email,
            user.username,
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
        """
        Handle user login.

        Returns:
            Response: JWT tokens and user data on success.
        """

        serializer = UserLoginSerializer(data=request.data)

        if not serializer.is_valid():
            # Log failed login attempt
            email = request.data.get("email", "unknown")
            auth_logger.warning(
                "Failed login attempt: email=%s, errors=%s, IP=%s",
                email,
                serializer.errors,
                get_client_ip(request),
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data["user"]

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)

        # Prepare response data
        token_data = {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": user,
        }

        # Serialize response
        response_serializer = TokenResponseSerializer(token_data)

        # Log successful login
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

        Returns:
            Response: Success message on successful logout.
        """
        try:
            refresh_token = request.data.get("refresh")

            if not refresh_token:
                auth_logger.warning(
                    "Logout failed: missing refresh token, user=%s, IP=%s",
                    request.user.email,
                    get_client_ip(request),
                )
                return Response(
                    {"detail": "Refresh token is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Blacklist the refresh token
            token = RefreshToken(refresh_token)
            token.blacklist()

            # Log successful logout
            auth_logger.info(
                "User logged out successfully: email=%s, username=%s, IP=%s",
                request.user.email,
                request.user.username,
                get_client_ip(request),
            )

            return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
        except TokenError as e:
            auth_logger.error(
                "Logout failed - invalid token: %s, user=%s, IP=%s",
                str(e),
                request.user.email,
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
                request.user.email,
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


# ==============================================================================
# CURRENT USER
# ==============================================================================


class CurrentUserView(generics.RetrieveUpdateAPIView):
    """
    API endpoint for current user profile.

    `GET /api/auth/me/`
    Returns the current authenticated user's profile data.

    `PUT /api/auth/me/`
    Updates the current user's profile (first_name, last_name).
    """

    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self) -> UserAccount:
        """
        Return the current authenticated user.

        Returns:
            UserAccount: The currently authenticated user.
        """
        return self.request.user

    def retrieve(self, request, *args, **kwargs) -> Response:
        """
        Get current user profile.

        Returns:
            Response: User profile data.
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance)

        # Log profile access
        logger.info(
            "User profile accessed: email=%s, IP=%s",
            request.user.email,
            get_client_ip(request),
        )

        return Response(serializer.data)

    def update(self, request, *args, **kwargs) -> Response:
        """
        Update current user profile.

        Only allows updating first_name and last_name.

        Returns:
            Response: Updated user profile data.
        """

        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        # Log profile update
        logger.info(
            "User profile updated: email=%s, updated_fields=%s, IP=%s",
            request.user.email,
            list(request.data.keys()),
            get_client_ip(request),
        )

        return Response(serializer.data)
