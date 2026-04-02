"""
Serializers for admin panel.

The module provides serializers for:
- Listing users (AdminUserListSerializer)
- Detailed user information (AdminUserDetailSerializer)
- Updating user data (AdminUserUpdateSerializer)
- Password reset (AdminPasswordResetSerializer)
- Toggling admin status (AdminToggleAdminSerializer)
"""

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from users.models import UserAccount

# ==================================================================================================
# ADMIN PANEL
# ==================================================================================================


class AdminUserListSerializer(serializers.ModelSerializer):
    """Serializer for listing users in admin panel."""

    class Meta:
        """Meta class for AdminUserListSerializer."""

        model = UserAccount
        fields = [
            "id",
            "username",
            "email",
            "is_active",
            "is_staff",
        ]
        read_only_fields = [
            "id",
            "username",
            "email",
        ]


class AdminUserDetailSerializer(serializers.ModelSerializer):
    """Serializer for detailed user information in admin panel."""

    full_name = serializers.SerializerMethodField()
    storage_path = serializers.CharField(read_only=True)

    class Meta:
        """Meta class for AdminUserDetailSerializer."""

        model = UserAccount
        fields = [
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "full_name",
            "is_staff",
            "is_active",
            "date_joined",
            "last_login",
            "storage_path",
        ]
        read_only_fields = [
            "id",
            "username",
            "email",
            "date_joined",
            "last_login",
            "storage_path",
        ]

    def get_full_name(self, obj) -> str:
        """Get user's full name."""
        return obj.get_full_name()


class AdminUserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user data by admin."""

    class Meta:
        """Meta class for AdminUserUpdateSerializer."""

        model = UserAccount
        fields = [
            "first_name",
            "last_name",
            "email",
            "is_active",
        ]

    def validate_email(self, value) -> str:
        """Ensure email is unique across all users except current."""

        user = self.context.get("request").user if self.context else None

        if user:
            existing = UserAccount.objects.filter(email=value).exclude(pk=user.pk)
            if existing.exists():
                raise serializers.ValidationError("Пользователь с таким email уже существует.")

        return value


class AdminPasswordResetSerializer(serializers.Serializer):
    """Serializer for admin password reset."""

    new_password = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
        help_text="Новый пароль пользователя",
    )

    def validate(self, attrs):
        """Validate password reset data."""

        new_password = attrs.get("new_password")

        try:
            validate_password(new_password)
        except DjangoValidationError as e:
            raise serializers.ValidationError({"new_password": list(e.messages)})

        return attrs

    def create(self, validated_data):
        """Not implemented for admin toggle serializer."""
        raise NotImplementedError("AdminToggleAdminSerializer does not implement create")

    def update(self, instance, validated_data):
        """Not implemented for admin toggle serializer."""
        raise NotImplementedError("AdminToggleAdminSerializer does not implement update")


class AdminToggleAdminSerializer(serializers.Serializer):
    """Serializer for toggling admin status."""

    is_staff = serializers.BooleanField(
        required=True,
        help_text="Статус администратора",
    )

    def create(self, validated_data):
        """Not implemented for admin toggle serializer."""
        raise NotImplementedError("AdminToggleAdminSerializer does not implement create")

    def update(self, instance, validated_data):
        """Not implemented for admin toggle serializer."""
        raise NotImplementedError("AdminToggleAdminSerializer does not implement update")
