"""
Custom password validators for UserAccount model.

The module contains validators for the following password requirements:
- minimum 6 characters
- at least one uppercase letter
- at least one digit
- at least one special character
"""

import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


class UppercaseValidator:
    """Validate that the password contains at least one uppercase letter."""

    def validate(self, password, user=None):
        """Validate that the password contains at least one uppercase letter."""
        if not re.search(r"[A-Z]", password):
            raise ValidationError(
                _("Пароль должен содержать хотя бы одну заглавную букву."),
                code="password_no_uppercase",
            )

    def get_help_text(self):
        """Get help text for the password validator."""
        return _("Ваш пароль должен содержать хотя бы одну заглавную букву.")


class LowercaseValidator:
    """Validate that the password contains at least one lowercase letter."""

    def validate(self, password, user=None):
        """Validate that the password contains at least one lowercase letter."""
        if not re.search(r"[a-z]", password):
            raise ValidationError(
                _("Пароль должен содержать хотя бы одну строчную букву."),
                code="password_no_lowercase",
            )

    def get_help_text(self):
        """Get help text for the password validator."""
        return _("Ваш пароль должен содержать хотя бы одну строчную букву.")


class DigitValidator:
    """Validate that the password contains at least one digit."""

    def validate(self, password, user=None):
        """Validate that the password contains at least one digit."""
        if not re.search(r"\d", password):
            raise ValidationError(
                _("Пароль должен содержать хотя бы одну цифру."),
                code="password_no_digit",
            )

    def get_help_text(self):
        """Get help text for the password validator."""
        return _("Ваш пароль должен содержать хотя бы одну цифру.")


class SpecialCharValidator:
    """Validate that the password contains at least one special character."""

    SPECIAL_CHARS = r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`]"

    def validate(self, password, user=None):
        """Validate that the password contains at least one special character."""
        if not re.search(self.SPECIAL_CHARS, password):
            raise ValidationError(
                _("Пароль должен содержать хотя бы один специальный символ (!@#$%^&*)."),
                code="password_no_special",
            )

    def get_help_text(self):
        """Get help text for the password validator."""
        return _("Ваш пароль должен содержать хотя бы один специальный символ (!@#$%^&*).")


class MinimumLengthValidator:
    """
    Custom minimum length validator with configurable length.
    Overrides default Django validator to enforce 6+ characters per Task.md.
    """

    def __init__(self, min_length=6):
        self.min_length = min_length

    def validate(self, password, user=None):
        """Validate that the password contains at least one special character."""
        if len(password) < self.min_length:
            raise ValidationError(
                _("Пароль должен содержать не менее %(min_length)d символов.")
                % {"min_length": self.min_length},
                code="password_too_short",
            )

    def get_help_text(self):
        """Get help text for the password validator."""
        return _("Ваш пароль должен содержать не менее %(min_length)d символов.") % {
            "min_length": self.min_length
        }
