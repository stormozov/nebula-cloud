"""
Module packeged serializers for users app.
"""

from .serializers_admin import (
    AdminPasswordResetSerializer,
    AdminToggleAdminSerializer,
    AdminUserDetailSerializer,
    AdminUserListSerializer,
    AdminUserUpdateSerializer,
)
from .serializers_auth import (
    TokenResponseSerializer,
    UserLoginSerializer,
    UserRegistrationSerializer,
)
from .serializers_users import PasswordChangeSerializer, UserSerializer

__all__ = [
    # User serializers
    "UserSerializer",
    "PasswordChangeSerializer",
    # Auth serializers
    "UserRegistrationSerializer",
    "UserLoginSerializer",
    "TokenResponseSerializer",
    # Admin serializers
    "AdminUserListSerializer",
    "AdminUserDetailSerializer",
    "AdminUserUpdateSerializer",
    "AdminToggleAdminSerializer",
    "AdminPasswordResetSerializer",
]
