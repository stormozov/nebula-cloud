"""
Serializers for user authentication and management.

The module provides serializers for:
- User profile management (UserSerializer)
- Password change (PasswordChangeSerializer)
"""

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from users.models import UserAccount

# ==================================================================================================
# USER PROFILE
# ==================================================================================================


class UserSerializer(serializers.ModelSerializer):
    """Serializer for user profile information."""

    full_name = serializers.SerializerMethodField(
        read_only=True,
        help_text="Полное имя пользователя",
    )
    storage_path = serializers.CharField(
        read_only=True,
        help_text="Путь к хранилищу пользователя",
    )

    class Meta:
        """Meta class for UserSerializer."""

        model = UserAccount
        fields = [
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "full_name",
            "storage_path",
            "date_joined",
            "last_login",
        ]
        read_only_fields = [
            "id",
            "username",
            "email",
            "date_joined",
            "last_login",
        ]

    def get_full_name(self, obj):
        """Get user's full name."""
        return obj.get_full_name()

    def update(self, instance, validated_data):
        """Update user profile."""

        instance.first_name = validated_data.get("first_name", instance.first_name)
        instance.last_name = validated_data.get("last_name", instance.last_name)
        instance.save()

        return instance


class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for password change."""

    current_password = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
        help_text="Текущий пароль пользователя",
    )
    new_password = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
        help_text="Новый пароль пользователя",
    )
    new_password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
        help_text="Подтверждение нового пароля",
    )

    def validate(self, attrs: dict) -> dict:
        """Validate password change data."""

        current_password = attrs.get("current_password")
        new_password = attrs.get("new_password")
        new_password_confirm = attrs.get("new_password_confirm")
        user = self.context.get("request").user

        # Check current password
        if not user.check_password(current_password):
            raise serializers.ValidationError({"current_password": "Неверный текущий пароль."})

        # Check password confirmation
        if new_password != new_password_confirm:
            raise serializers.ValidationError({"new_password_confirm": "Пароли не совпадают."})

        # Check if new password is same as current
        if user.check_password(new_password):
            raise serializers.ValidationError(
                {"new_password": "Новый пароль не должен совпадать с текущим."}
            )

        # Validate new password with Django validators
        try:
            validate_password(new_password, user=user)
        except DjangoValidationError as e:
            raise serializers.ValidationError({"new_password": list(e.messages)}) from e

        return attrs

    def create(self, validated_data):
        """Not implemented for password change serializer."""
        raise NotImplementedError("PasswordChangeSerializer does not implement create")

    def update(self, instance, validated_data):
        """Not implemented for password change serializer."""
        raise NotImplementedError("PasswordChangeSerializer does not implement update")
