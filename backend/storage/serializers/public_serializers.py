"""
Serializers for file listing and read operations.

- FileSerializer
- PublicFileSerializer
"""

from rest_framework import serializers

from core.utils import format_size
from storage.models import File


class PublicFileSerializer(serializers.ModelSerializer):
    """
    Serializer for public file preview (before download via public link).
    Minimal safe metadata only. No owner info, no internal paths.
    """

    download_url = serializers.SerializerMethodField()
    size_formatted = serializers.SerializerMethodField()

    class Meta:
        """Meta class for PublicFileSerializer."""

        model = File
        fields = [
            "original_name",
            "size",
            "size_formatted",
            "uploaded_at",
            "comment",
            "download_url",
        ]
        read_only_fields = fields

    def get_download_url(self, obj):
        """Public download URL (no auth required)."""
        request = self.context.get("request")
        url = f"/api/storage/public/{obj.public_link}/download/"
        return request.build_absolute_uri(url) if request else url

    def get_size_formatted(self, obj):
        """Reuse formatting logic."""
        return format_size(obj.size)


class FilePublicLinkSerializer(serializers.Serializer):
    """
    Serializer for generating/deleting public link.
    Action must be 'generate' or 'delete'.
    """

    ACTION_CHOICES = (
        ("generate", "Создать публичную ссылку"),
        ("delete", "Удалить публичную ссылку"),
    )
    action = serializers.ChoiceField(choices=ACTION_CHOICES)

    def validate(self, attrs: dict) -> dict:
        file_instance = self.context.get("file_instance")

        if attrs["action"] == "generate" and file_instance.public_link:
            raise serializers.ValidationError(
                {
                    "detail": "Публичная ссылка уже существует",
                    "public_link": file_instance.public_link,
                }
            )
        if attrs["action"] == "delete" and not file_instance.public_link:
            raise serializers.ValidationError({"detail": "Публичная ссылка отсутствует"})

        return attrs

    def create(self, validated_data: dict) -> None:
        """Not implemented for public link serializer."""
        return NotImplementedError("Public link serializer does not implement create")

    def update(self, instance: File, validated_data: dict) -> File:
        """Not implemented for public link serializer."""
        return NotImplementedError("Public link serializer does not implement update")

    def save(self, *args, **kwargs):  # pylint: disable=unused-argument
        file_instance = self.context.get("file_instance")
        action = self.validated_data.get("action")

        if action == "generate":
            file_instance.generate_public_link(force=True)
        elif action == "delete":
            file_instance.public_link = None
            file_instance.save(update_fields=["public_link"])

        return file_instance
