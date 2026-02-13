"""
Module for custom user model.
"""

from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from django.db import models
from django.utils.translation import gettext_lazy as _

from users.managers import UserAccountManager


class UserAccount(AbstractUser):
    """Custom user model."""

    username_validator = RegexValidator(
        regex=r"^[a-zA-Z][a-zA-Z0-9]{3,19}$",
        message=_(
            "Логин должен содержать только латинские буквы и цифры, "
            "начинаться с буквы и быть длиной от 4 до 20 символов."
        ),
    )

    username = models.CharField(
        _("логин"),
        max_length=20,
        unique=True,
        validators=[username_validator],
        error_messages={"unique": _("Пользователь с таким логином уже существует.")},
    )

    email = models.EmailField(
        _("email"),
        unique=True,
        max_length=254,
        error_messages={"unique": _("Пользователь с таким email уже существует.")},
    )

    first_name = models.CharField(
        _("имя"),
        max_length=150,
    )

    last_name = models.CharField(
        _("фамилия"),
        max_length=150,
    )

    objects = UserAccountManager()

    @property
    def storage_path(self) -> str:
        """Path to user's storage."""
        return f"storage/{self.pk}/"

    class Meta:
        """Settings for UserAccount model."""

        db_table = "users_useraccount"
        app_label = "users"
        verbose_name = _("пользователь")
        verbose_name_plural = _("пользователи")
        ordering = ["username"]

    def __str__(self):
        return f"{self.username} ({self.email})"

    def is_admin_user(self) -> bool:
        """Check if user is admin."""
        return self.is_staff or self.is_superuser

    def get_full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"
