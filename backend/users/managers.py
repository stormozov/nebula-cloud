"""
Module for custom user manager.
"""

from django.contrib.auth.base_user import BaseUserManager
from django.utils.translation import gettext_lazy as _


class UserAccountManager(BaseUserManager):
    """Manager for UserAccount model."""

    def create_user(
        self, username, email, first_name="", last_name="", password=None, **extra_fields
    ):
        """Create and save a UserAccount with the given email and password."""
        if not username:
            raise ValueError(_("Пользователь должен иметь логин"))

        if not email:
            raise ValueError(_("Пользователь должен иметь email"))

        email = self.normalize_email(email)
        user = self.model(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            **extra_fields,
        )
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(
        self, username, email, first_name="", last_name="", password=None, **extra_fields
    ):
        """Create and save a SuperUser with the given email and password."""

        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Суперпользователь должен иметь is_staff=True."))

        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Суперпользователь должен иметь is_superuser=True."))

        return self.create_user(username, email, first_name, last_name, password, **extra_fields)
