"""Services for admin user management business logic."""

from django.db import models

from core.utils import format_size
from storage.models import File
from users.exceptions import AdminUserActionError
from users.models import UserAccount


def get_user_by_id_or_raise(user_id: int) -> UserAccount:
    """Get user by ID or raise ObjectDoesNotExist."""
    return UserAccount.objects.get(pk=user_id)


def validate_not_self_action(admin: UserAccount, target: UserAccount, action: str) -> None:
    """
    Validate that admin is not performing restricted action on themselves.

    Raises:
        AdminUserActionError: if action is not permitted on self
    """

    if admin.id == target.id:
        messages = {
            "delete": "Нельзя удалить собственную учётную запись.",
            "password_reset": "Используйте endpoint смены пароля для себя.",
            "toggle_admin": "Нельзя изменить собственный статус администратора.",
        }
        raise AdminUserActionError(
            messages.get(action, "Недопустимое действие над собственной учётной записью.")
        )


def calculate_storage_stats(user: UserAccount) -> dict:
    """Calculate storage statistics for a user."""

    user_files = File.objects.filter(owner=user)  # pylint: disable=no-member
    total_size = user_files.aggregate(total=models.Sum("size"))["total"] or 0
    file_count = user_files.count()
    storage_limit = user.storage_limit

    usage_percent = (total_size / storage_limit * 100) if storage_limit > 0 else 0

    return {
        "file_count": file_count,
        "total_size": total_size,
        "total_size_formatted": format_size(total_size),
        "storage_limit": storage_limit,
        "storage_limit_formatted": format_size(storage_limit),
        "usage_percent": round(usage_percent, 2),
    }


def reset_user_password(user: UserAccount, new_password: str) -> None:
    """Reset user password securely."""
    user.set_password(new_password)
    user.save(update_fields=["password"])


def toggle_admin_status(user: UserAccount, is_admin: bool) -> None:
    """Toggle user admin (staff) status."""
    user.is_staff = is_admin
    user.save(update_fields=["is_staff"])
