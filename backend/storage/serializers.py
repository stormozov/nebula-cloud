"""
Serializers for File model operations.
"""

from rest_framework import serializers

from storage.utils import validate_file_size, validate_filename

from .models import File


class FileSerializer(serializers.ModelSerializer):
    """
    Base serializer for file listing (authenticated users and admin).
    Returns safe, user-facing file metadata.
    """

    has_public_link = serializers.SerializerMethodField()
    public_link_url = serializers.SerializerMethodField()
    download_url = serializers.SerializerMethodField()
    size_formatted = serializers.SerializerMethodField()

    class Meta:
        """Meta class for FileSerializer."""

        model = File
        fields = [
            "id",
            "original_name",
            "comment",
            "size",
            "size_formatted",
            "uploaded_at",
            "last_downloaded",
            "has_public_link",
            "public_link_url",
            "download_url",
        ]
        read_only_fields = fields

    def get_has_public_link(self, obj: File) -> bool:
        """Return True if public link exists."""
        return bool(obj.public_link)

    def get_public_link_url(self, obj: File) -> str | None:
        """Return full public URL if link exists."""
        if not obj.public_link:
            return None

        request = self.context.get("request")
        return (
            request.build_absolute_uri(f"/api/storage/public/{obj.public_link}/")
            if request
            else f"/api/storage/public/{obj.public_link}/"
        )

    def get_download_url(self, obj: File) -> str:
        """Return authenticated download URL."""
        request = self.context.get("request")
        return (
            request.build_absolute_uri(f"/api/storage/files/{obj.id}/download/")
            if request
            else f"/api/storage/files/{obj.id}/download/"
        )

    def get_size_formatted(self, obj: File) -> str:
        """Convert bytes to human-readable format (KB/MB/GB)."""

        size = obj.size
        for unit in ["Б", "КБ", "МБ", "ГБ"]:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0

        return f"{size:.2f} ТБ"


class FileUploadSerializer(serializers.ModelSerializer):
    """
    Serializer for file upload with comment.
    Handles extraction of original_name and size from uploaded file.
    """

    file = serializers.FileField(validators=[validate_file_size])
    comment = serializers.CharField(max_length=500, required=False, allow_blank=True)

    class Meta:
        """Meta class for FileUploadSerializer."""

        model = File
        fields = ["file", "comment"]
        extra_kwargs = {"file": {"required": True}}

    def validate_file(self, value: File) -> File:
        """Validate file."""
        return value

    def create(self, validated_data: dict) -> File:
        """
        Extract metadata from uploaded file and set owner from request context.
        Owner must be injected in viewset before calling serializer.save().
        """

        uploaded_file = validated_data.get("file")
        validated_data["original_name"] = uploaded_file.name
        validated_data["size"] = uploaded_file.size

        return super().create(validated_data)


class FileRenameSerializer(serializers.Serializer):
    """
    Serializer for renaming file (changes original_name only).
    """

    original_name = serializers.CharField(max_length=255, validators=[validate_filename])

    def create(self, validated_data: dict) -> None:
        """Not implemented for rename serializer."""
        return NotImplementedError("Rename serializer does not implement create")

    def update(self, instance: File, validated_data: dict) -> File:
        instance.original_name = validated_data.get("original_name", instance.original_name)
        instance.save(update_fields=["original_name"])
        return instance


class FileCommentSerializer(serializers.Serializer):
    """
    Serializer for updating/deleting file comment.
    Empty string clears the comment.
    """

    comment = serializers.CharField(max_length=1000, required=False, allow_blank=True)

    def create(self, validated_data: dict) -> None:
        """Not implemented for comment serializer."""
        return NotImplementedError("Comment serializer does not implement create")

    def update(self, instance: File, validated_data: dict) -> File:
        instance.comment = validated_data.get("comment", instance.comment)
        instance.save(update_fields=["comment"])
        return instance


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

    def save(self):  # pylint: disable=arguments-differ
        file_instance = self.context.get("file_instance")
        action = self.validated_data.get("action")

        if action == "generate":
            file_instance.generate_public_link(force=True)
        elif action == "delete":
            file_instance.public_link = None
            file_instance.save(update_fields=["public_link"])

        return file_instance


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

        size = obj.size

        for unit in ["Б", "КБ", "МБ", "ГБ"]:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0

        return f"{size:.2f} ТБ"
