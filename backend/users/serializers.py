"""
Serializers for user authentication and management.
"""

from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from users.models import UserAccount

# ==============================================================================
# REGISTRATION AND LOGIN
# ==============================================================================


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""

    password = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
        help_text="Пароль пользователя",
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
        help_text="Подтверждение пароля",
    )

    class Meta:
        """Meta class for UserRegistrationSerializer."""

        model = UserAccount
        fields = [
            "username",
            "email",
            "first_name",
            "last_name",
            "password",
            "password_confirm",
        ]
        extra_kwargs = {
            "first_name": {"required": True},
            "last_name": {"required": True},
        }

    def validate(self, attrs):
        """Validate password confirmation and other fields."""
        if attrs["password"] != attrs["password_confirm"]:
            raise serializers.ValidationError({"password_confirm": "Пароли не совпадают."})

        try:
            validate_password(attrs["password"])
        except DjangoValidationError as e:
            raise serializers.ValidationError({"password": list(e.messages)}) from e

        return attrs

    def create(self, validated_data):
        """Create and return a new user."""
        validated_data.pop("password_confirm")

        user = UserAccount.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
        )

        return user


class UserLoginSerializer(serializers.Serializer):
    """Serializer for user login."""

    username = serializers.CharField(
        required=True,
        help_text="Логин пользователя",
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
        help_text="Пароль пользователя",
    )

    def validate(self, attrs):
        """Validate user credentials."""
        username = attrs.get("username")
        password = attrs.get("password")

        user = authenticate(username=username, password=password)

        if not user:
            raise serializers.ValidationError({"detail": "Неверный логин или пароль."})

        if not user.is_active:
            raise serializers.ValidationError({"detail": "Пользователь неактивен."})

        attrs["user"] = user
        return attrs

    def create(self, validated_data):
        """Not implemented for login serializer."""
        raise NotImplementedError("Login serializer does not implement create")

    def update(self, instance, validated_data):
        """Not implemented for login serializer."""
        raise NotImplementedError("Login serializer does not implement update")


# ==============================================================================
# TOKENS
# ==============================================================================


class TokenResponseSerializer(serializers.Serializer):
    """Serializer for JWT token response."""

    access = serializers.CharField(
        read_only=True,
        help_text="Access token (JWT)",
    )
    refresh = serializers.CharField(
        read_only=True,
        help_text="Refresh token (JWT)",
    )
    user = serializers.SerializerMethodField(
        read_only=True,
        help_text="User information",
    )

    def get_user(self, obj):
        """Get user data for token response."""
        user = obj.get("user")

        if user:
            return {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "full_name": user.get_full_name(),
            }

        return None

    def create(self, validated_data):
        """Not implemented for token response serializer."""
        raise NotImplementedError("TokenResponseSerializer does not implement create")

    def update(self, instance, validated_data):
        """Not implemented for token response serializer."""
        raise NotImplementedError("TokenResponseSerializer does not implement update")


# ==============================================================================
# USER PROFILE
# ==============================================================================


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
