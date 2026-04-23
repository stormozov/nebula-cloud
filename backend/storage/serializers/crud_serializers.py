"""
Serializers for file write operations:
- upload (FileUploadSerializer)
- rename (FileRenameSerializer)
- comment (FileCommentSerializer)
- public link (FilePublicLinkSerializer)
"""

from rest_framework import serializers

from core.utils import format_size
from storage.models import File
from storage.utils import get_public_frontend_url, validate_file_size, validate_filename


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
        read_only_fields = [
            "id",
            "size",
            "size_formatted",
            "uploaded_at",
            "last_downloaded",
            "has_public_link",
            "public_link_url",
            "download_url",
        ]
        extra_kwargs = {
            "original_name": {"validators": [validate_filename]},
            "comment": {"max_length": 1000, "allow_blank": True, "required": False},
        }

    def get_has_public_link(self, obj: File) -> bool:
        """Return True if public link exists."""
        return bool(obj.public_link)

    def get_public_link_url(self, obj: File) -> str | None:
        """Return frontend public URL if link exists."""
        return get_public_frontend_url(obj.public_link) if obj.public_link else None

    def get_download_url(self, obj: File) -> str:
        """Return authenticated download URL."""
        request = self.context.get("request")
        return (
            request.build_absolute_uri(f"/api/storage/files/{obj.id}/download/")
            if request
            else f"/api/storage/files/{obj.id}/download/"
        )

    def get_size_formatted(self, obj: File) -> str:
        """Convert bytes to human-readable format."""
        return format_size(obj.size)


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

    original_name = serializers.CharField(
        max_length=255, validators=[validate_filename], trim_whitespace=False
    )

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
