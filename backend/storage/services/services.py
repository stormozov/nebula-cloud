from django.db import transaction
from django.db.models import Sum
from rest_framework.exceptions import ValidationError

from storage.models import File
from storage.serializers import FileUploadSerializer
from users.models import UserAccount


def create_file_with_limit_check(
    *,
    user: UserAccount,
    upload_serializer: FileUploadSerializer,
    request=None,
) -> File:
    """
    Checks the storage limit and creates a file.

    Raises:
        ValidationError: if the limit is exceeded
    """

    uploaded_file = upload_serializer.validated_data["file"]
    file_size = uploaded_file.size

    with transaction.atomic():
        user_locked = UserAccount.objects.select_for_update().get(pk=user.pk)
        current_total = File.objects.filter(owner=user).aggregate(total=Sum("size"))["total"] or 0

        if current_total + file_size > user_locked.storage_limit:
            raise ValidationError(
                detail="Превышен лимит хранилища. Освободите место.",
                code="storage_limit_exceeded",
            )

        file_obj = upload_serializer.save(owner=user)
        return file_obj
