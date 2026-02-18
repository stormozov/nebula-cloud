"""
Utils for storage app.
"""

import os
import re

from django.conf import settings
from nanoid import generate
from rest_framework import serializers


def generate_unique_path(instance: object, filename: str) -> str:
    """Generate unique path for file: `storage/{user_id}/{prefix}/{unique_id}{ext}`"""

    user_id = instance.owner.id
    ext = os.path.splitext(filename)[1].lower()
    unique_id = generate(size=12)
    prefix = unique_id[:2]

    return f"storage/{user_id}/{prefix}/{unique_id}{ext}"


def validate_file_size(file):
    """Validate file size does not exceed 100 MB."""

    if file.size > settings.MAX_UPLOAD_SIZE:
        raise serializers.ValidationError(f"Размер файла превышает допустимый лимит (100 МБ). \
                Текущий размер: {file.size / (1024 * 1024):.2f} МБ")

    return file


def validate_filename(value):
    """
    Validate filename does not contain forbidden characters.

    Forbidden: \\ / : * ? " < > |
    Also rejected: trailing dot (.), trailing space ( ), empty string
    """

    if not value or not value.strip():
        raise serializers.ValidationError("Имя файла не может быть пустым")

    # Check for forbidden characters
    forbidden_chars = r'[\\/:*?"<>|]'
    if re.search(forbidden_chars, value):
        raise serializers.ValidationError(
            'Имя файла содержит запрещённые символы: \\ / : * ? " < > |'
        )

    # Check for trailing dot or space
    if value.endswith(".") or value.endswith(" "):
        raise serializers.ValidationError("Имя файла не может заканчиваться точкой или пробелом")

    return value.strip()
