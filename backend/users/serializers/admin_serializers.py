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
from django.db import models
from rest_framework import serializers

from core.utils import format_size
from storage.models import File
from users.models import UserAccount

# ==================================================================================================
# ADMIN PANEL
# ==================================================================================================


class AdminUserListSerializer(serializers.ModelSerializer):
    """Serializer for listing users in admin panel."""

    full_name = serializers.SerializerMethodField()
    is_admin = serializers.BooleanField(source="is_staff", read_only=True)
    storage_stats = serializers.SerializerMethodField()

    class Meta:
        """Meta class for AdminUserListSerializer."""

        model = UserAccount
        fields = [
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "full_name",
            "is_admin",
            "is_active",
            "date_joined",
            "last_login",
            "storage_stats",
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

    def get_storage_stats(self, obj):
        """Get user's storage statistics."""

        user_files = File.objects.filter(owner=obj)  # pylint: disable=no-member
        total_size = user_files.aggregate(total=models.Sum("size"))["total"] or 0
        file_count = user_files.count()

        return {
            "file_count": file_count,
            "total_size": total_size,
            "total_size_formatted": format_size(total_size),
        }


class AdminUserDetailSerializer(serializers.ModelSerializer):
    """Serializer for detailed user information in admin panel."""

    full_name = serializers.SerializerMethodField()
    is_admin = serializers.BooleanField(source="is_staff", read_only=True)
    storage_path = serializers.CharField(read_only=True)
    storage_stats = serializers.SerializerMethodField()

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
            "is_admin",
            "is_active",
            "date_joined",
            "last_login",
            "storage_path",
            "storage_stats",
        ]
        read_only_fields = [
            "id",
            "username",
            "email",
            "date_joined",
            "last_login",
            "storage_path",
        ]

    def get_full_name(self, obj):
        """Get user's full name."""
        return obj.get_full_name()

    def get_storage_stats(self, obj):
        """Get user's storage statistics."""

        user_files = File.objects.filter(owner=obj)  # pylint: disable=no-member
        total_size = user_files.aggregate(total=models.Sum("size"))["total"] or 0
        file_count = user_files.count()

        return {
            "file_count": file_count,
            "total_size": total_size,
            "total_size_formatted": format_size(total_size),
        }


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

    def validate_email(self, value):
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
    new_password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
        help_text="Подтверждение нового пароля",
    )

    def validate(self, attrs):
        """Validate password reset data."""

        new_password = attrs.get("new_password")
        new_password_confirm = attrs.get("new_password_confirm")

        # Check password confirmation
        if new_password != new_password_confirm:
            raise serializers.ValidationError({"new_password_confirm": "Пароли не совпадают."})

        # Validate new password with Django validators
        try:
            validate_password(new_password)
        except DjangoValidationError as e:
            raise serializers.ValidationError({"new_password": list(e.messages)}) from e

        return attrs

    def create(self, validated_data):
        """Not implemented for admin toggle serializer."""
        raise NotImplementedError("AdminToggleAdminSerializer does not implement create")

    def update(self, instance, validated_data):
        """Not implemented for admin toggle serializer."""
        raise NotImplementedError("AdminToggleAdminSerializer does not implement update")


class AdminToggleAdminSerializer(serializers.Serializer):
    """Serializer for toggling admin status."""

    is_admin = serializers.BooleanField(
        required=True,
        help_text="Статус администратора",
    )

    def create(self, validated_data):
        """Not implemented for admin toggle serializer."""
        raise NotImplementedError("AdminToggleAdminSerializer does not implement create")

    def update(self, instance, validated_data):
        """Not implemented for admin toggle serializer."""
        raise NotImplementedError("AdminToggleAdminSerializer does not implement update")
