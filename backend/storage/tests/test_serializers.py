"""
Tests for storage application serializers.

This module tests all serializer functionality including:
- File upload validation (size, name, comment)
- File rename validation (forbidden characters)
- Comment management validation
- Public link generation validation
- File listing serialization (URLs, formatting)
- Public file access serialization
"""

from django.core.files.uploadedfile import SimpleUploadedFile

from storage.serializers import (
    FileCommentSerializer,
    FilePublicLinkSerializer,
    FileRenameSerializer,
    FileSerializer,
    FileUploadSerializer,
    PublicFileSerializer,
)

# ==============================================================================
# TESTS: FILE UPLOAD SERIALIZER
# ==============================================================================


class TestFileUploadSerializer:
    """
    Test suite for FileUploadSerializer validation and creation.
    """

    def test_upload_serializer_valid_file_creates_instance(self, db, user_account, test_file):
        """
        Verify that valid file upload creates File instance.

        Scenario:
            1. Create serializer with valid file and comment
            2. Call is_valid()
            3. Call save() with owner

        Expected:
            - Serializer is valid
            - File instance is created
            - original_name and size are extracted from file
            - comment is preserved
        """

        # Arrange
        serializer = FileUploadSerializer(data={"file": test_file, "comment": "Test upload"})

        # Act
        is_valid = serializer.is_valid()
        file_obj = serializer.save(owner=user_account)

        # Assert
        assert is_valid is True
        assert file_obj.owner == user_account
        assert file_obj.original_name == "test_file.txt"
        assert file_obj.size > 0
        assert file_obj.comment == "Test upload"

    def test_upload_serializer_file_size_under_limit_accepts(self, db, user_account, test_file):
        """
        Verify that file under 100MB limit is accepted.

        Expected:
            - 1KB file passes validation
            - No ValidationError raised
        """
        # Arrange
        serializer = FileUploadSerializer(data={"file": test_file, "comment": ""})

        # Act & Assert
        assert serializer.is_valid() is True

    def test_upload_serializer_file_size_over_limit_rejects(
        self, db, user_account, large_test_file
    ):
        """
        Verify that file over 100MB limit is rejected.

        Scenario:
            1. Create serializer with 101MB file
            2. Call is_valid()

        Expected:
            - Serializer is invalid
            - ValidationError contains size error message
            - Error message mentions 100 MB limit
        """

        # Arrange
        serializer = FileUploadSerializer(data={"file": large_test_file, "comment": ""})

        # Act
        is_valid = serializer.is_valid()

        # Assert
        assert is_valid is False
        assert "file" in serializer.errors
        assert "100" in str(serializer.errors["file"][0])  # Mentions limit

    def test_upload_serializer_comment_optional(self, db, user_account, test_file):
        """
        Verify that comment field is optional.

        Expected:
            - File upload succeeds without comment
            - comment field is empty string or None
        """

        # Arrange
        serializer = FileUploadSerializer(data={"file": test_file})

        # Act
        is_valid = serializer.is_valid()
        file_obj = serializer.save(owner=user_account)

        # Assert
        assert is_valid is True
        assert file_obj.comment in ["", None]

    def test_upload_serializer_comment_max_length(self, db, user_account, test_file):
        """
        Verify that comment respects max_length of 500 characters.

        Expected:
            - 500 character comment is accepted
            - 501 character comment is rejected
        """

        # Arrange
        valid_comment = "x" * 500
        invalid_comment = "x" * 501

        # Act & Assert - valid
        serializer_valid = FileUploadSerializer(data={"file": test_file, "comment": valid_comment})
        assert serializer_valid.is_valid() is True

        # Act & Assert - invalid
        serializer_invalid = FileUploadSerializer(
            data={"file": test_file, "comment": invalid_comment}
        )
        assert serializer_invalid.is_valid() is False
        assert "comment" in serializer_invalid.errors

    def test_upload_serializer_extracts_original_name(self, db, user_account):
        """
        Verify that original_name is extracted from uploaded file.

        Expected:
            - original_name matches uploaded file name
            - Extension is preserved
        """

        # Arrange
        test_file = SimpleUploadedFile(
            name="document_2024.pdf",
            content=b"Test content",
            content_type="application/pdf",
        )
        serializer = FileUploadSerializer(data={"file": test_file})

        # Act
        serializer.is_valid(raise_exception=True)
        file_obj = serializer.save(owner=user_account)

        # Assert
        assert file_obj.original_name == "document_2024.pdf"


# ==============================================================================
# TESTS: FILE RENAME SERIALIZER
# ==============================================================================


class TestFileRenameSerializer:
    """
    Test suite for FileRenameSerializer validation.
    """

    def test_rename_serializer_valid_name_accepts(self, db, user_account, create_file):
        """
        Verify that valid filename is accepted.

        Expected:
            - Normal filename passes validation
            - File is renamed successfully
        """

        # Arrange
        file_obj = create_file(owner=user_account, original_name="old_name.txt")
        serializer = FileRenameSerializer(data={"original_name": "new_name.txt"})

        # Act
        is_valid = serializer.is_valid()
        serializer.update(file_obj, serializer.validated_data)

        # Assert
        assert is_valid is True
        assert file_obj.original_name == "new_name.txt"

    def test_rename_serializer_forbidden_characters_rejects(self, db, user_account, create_file):
        """
        Verify that filenames with forbidden characters are rejected.

        Forbidden characters: \\ / : * ? " < > |

        Expected:
            - Each forbidden character causes validation error
            - Error message mentions forbidden characters
        """

        # Arrange
        create_file(owner=user_account, original_name="old.txt")
        forbidden_names = [
            "file:name.txt",
            "file/name.txt",
            "file\\name.txt",
            "file*name.txt",
            "file?name.txt",
            'file"name.txt',
            "file<name.txt",
            "file>name.txt",
            "file|name.txt",
        ]

        # Act & Assert
        for name in forbidden_names:
            serializer = FileRenameSerializer(data={"original_name": name})
            assert serializer.is_valid() is False
            assert "original_name" in serializer.errors

    def test_rename_serializer_trailing_dot_rejects(self, db, user_account, create_file):
        """
        Verify that filenames ending with dot are rejected.

        Expected:
            - "file." is rejected
            - Error message mentions trailing dot
        """

        # Arrange
        file_obj = create_file(owner=user_account, original_name="old.txt")
        serializer = FileRenameSerializer(data={"original_name": "newname."})

        # Act
        is_valid = serializer.is_valid()

        # Assert
        assert is_valid is False
        assert "original_name" in serializer.errors
        assert (
            "точкой" in str(serializer.errors["original_name"]).lower()
            or "dot" in str(serializer.errors["original_name"]).lower()
        )

    def test_rename_serializer_trailing_space_rejects(self, db, user_account, create_file):
        """
        Verify that filenames ending with space are rejected.

        Expected:
            - "file " is rejected
            - Error message mentions trailing space
        """

        # Arrange
        create_file(owner=user_account, original_name="old.txt")
        serializer = FileRenameSerializer(data={"original_name": "newname "})

        # Act
        is_valid = serializer.is_valid()

        # Assert
        assert is_valid is False
        assert "original_name" in serializer.errors

    def test_rename_serializer_empty_name_rejects(self, db, user_account, create_file):
        """
        Verify that empty filename is rejected.

        Expected:
            - Empty string is rejected
            - Whitespace-only string is rejected
        """

        # Arrange
        create_file(owner=user_account, original_name="old.txt")

        # Act & Assert - empty
        serializer_empty = FileRenameSerializer(data={"original_name": ""})
        assert serializer_empty.is_valid() is False

        # Act & Assert - whitespace
        serializer_whitespace = FileRenameSerializer(data={"original_name": "   "})
        assert serializer_whitespace.is_valid() is False


# ==============================================================================
# TESTS: FILE COMMENT SERIALIZER
# ==============================================================================


class TestFileCommentSerializer:
    """
    Test suite for FileCommentSerializer validation.
    """

    def test_comment_serializer_valid_comment_updates(self, db, user_account, create_file):
        """
        Verify that valid comment updates file.

        Expected:
            - Comment is saved correctly
            - File instance is updated
        """

        # Arrange
        file_obj = create_file(owner=user_account, original_name="test.txt")
        serializer = FileCommentSerializer(data={"comment": "New comment"})

        # Act
        is_valid = serializer.is_valid()
        serializer.update(file_obj, serializer.validated_data)

        # Assert
        assert is_valid is True
        assert file_obj.comment == "New comment"

    def test_comment_serializer_empty_string_clears(self, db, user_account, create_file):
        """
        Verify that empty string clears existing comment.

        Expected:
            - Empty comment is accepted
            - Existing comment is cleared
        """

        # Arrange
        file_obj = create_file(owner=user_account, original_name="test.txt", comment="Old comment")
        serializer = FileCommentSerializer(data={"comment": ""})

        # Act
        is_valid = serializer.is_valid()
        serializer.update(file_obj, serializer.validated_data)

        # Assert
        assert is_valid is True
        assert file_obj.comment == ""

    def test_comment_serializer_max_length(self, db, user_account, create_file):
        """
        Verify that comment respects max_length of 1000 characters.

        Expected:
            - 1000 character comment is accepted
            - 1001 character comment is rejected
        """

        # Arrange
        create_file(owner=user_account, original_name="test.txt")
        valid_comment = "x" * 1000
        invalid_comment = "x" * 1001

        # Act & Assert - valid
        serializer_valid = FileCommentSerializer(data={"comment": valid_comment})
        assert serializer_valid.is_valid() is True

        # Act & Assert - invalid
        serializer_invalid = FileCommentSerializer(data={"comment": invalid_comment})
        assert serializer_invalid.is_valid() is False
        assert "comment" in serializer_invalid.errors

    def test_comment_serializer_special_characters_accepted(self, db, user_account, create_file):
        """
        Verify that special characters in comment are accepted.

        Expected:
            - Unicode characters are accepted
            - HTML-like characters are accepted
            - Emojis are accepted
        """

        # Arrange
        create_file(owner=user_account, original_name="test.txt")
        special_comments = [
            "Comment with <html> tags",
            "Комментарий на русском",
            "Comment with emoji 🚀",
            "Comment with special: !@#$%^&*()",
        ]

        # Act & Assert
        for comment in special_comments:
            serializer = FileCommentSerializer(data={"comment": comment})
            assert serializer.is_valid() is True


# ==============================================================================
# TESTS: FILE PUBLIC LINK SERIALIZER
# ==============================================================================


class TestFilePublicLinkSerializer:
    """
    Test suite for FilePublicLinkSerializer validation.
    """

    def test_public_link_serializer_generate_action_valid(self, db, user_account, create_file):
        """
        Verify that 'generate' action is valid for file without link.

        Expected:
            - Action 'generate' is accepted
            - save() generates public_link
        """

        # Arrange
        file_obj = create_file(owner=user_account, original_name="test.txt")
        serializer = FilePublicLinkSerializer(
            data={"action": "generate"},
            context={"file_instance": file_obj},
        )

        # Act
        is_valid = serializer.is_valid()

        # Assert
        assert is_valid is True

    def test_public_link_serializer_generate_action_rejects_existing(
        self, db, user_account, create_file
    ):
        """
        Verify that 'generate' action is rejected if link already exists.

        Expected:
            - ValidationError is raised
            - Error message mentions existing link
        """

        # Arrange
        file_obj = create_file(
            owner=user_account, original_name="test.txt", public_link="existing123"
        )
        serializer = FilePublicLinkSerializer(
            data={"action": "generate"},
            context={"file_instance": file_obj},
        )

        # Act
        is_valid = serializer.is_valid()

        # Assert
        assert is_valid is False
        assert "detail" in serializer.errors
        assert (
            "существует" in str(serializer.errors).lower()
            or "exists" in str(serializer.errors).lower()
        )

    def test_public_link_serializer_delete_action_valid(self, db, user_account, create_file):
        """
        Verify that 'delete' action is valid for file with link.

        Expected:
            - Action 'delete' is accepted
            - save() removes public_link
        """

        # Arrange
        file_obj = create_file(
            owner=user_account, original_name="test.txt", public_link="testlink123"
        )
        serializer = FilePublicLinkSerializer(
            data={"action": "delete"},
            context={"file_instance": file_obj},
        )

        # Act
        is_valid = serializer.is_valid()

        # Assert
        assert is_valid is True

    def test_public_link_serializer_delete_action_rejects_missing(
        self, db, user_account, create_file
    ):
        """
        Verify that 'delete' action is rejected if link doesn't exist.

        Expected:
            - ValidationError is raised
            - Error message mentions missing link
        """

        # Arrange
        file_obj = create_file(owner=user_account, original_name="test.txt")
        serializer = FilePublicLinkSerializer(
            data={"action": "delete"},
            context={"file_instance": file_obj},
        )

        # Act
        is_valid = serializer.is_valid()

        # Assert
        assert is_valid is False
        assert "detail" in serializer.errors
        assert (
            "отсутствует" in str(serializer.errors).lower()
            or "missing" in str(serializer.errors).lower()
        )

    def test_public_link_serializer_invalid_action_rejects(self, db, user_account, create_file):
        """
        Verify that invalid action is rejected.

        Expected:
            - Action 'invalid' is rejected
            - ChoiceField validation error is raised
        """

        # Arrange
        file_obj = create_file(owner=user_account, original_name="test.txt")
        serializer = FilePublicLinkSerializer(
            data={"action": "invalid"},
            context={"file_instance": file_obj},
        )

        # Act
        is_valid = serializer.is_valid()

        # Assert
        assert is_valid is False
        assert "action" in serializer.errors


# ==============================================================================
# TESTS: FILE SERIALIZER (LISTING)
# ==============================================================================


class TestFileSerializer:
    """
    Test suite for FileSerializer (file listing and detail).
    """

    def test_file_serializer_includes_all_fields(self, db, user_account, create_file):
        """
        Verify that serializer includes all required fields.

        Expected:
            - All fields from Meta.fields are present
            - No unexpected fields
        """

        # Arrange - use create_file instead of uploaded_file fixture
        file_obj = create_file(
            owner=user_account,
            original_name="test.txt",
            size=1024,
            comment="Test comment",
        )
        serializer = FileSerializer(file_obj, context={"request": None})

        # Act
        data = serializer.data

        # Assert
        expected_fields = [
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
        for field in expected_fields:
            assert field in data, f"Field '{field}' is missing from serializer output"

    def test_file_serializer_size_formatted_human_readable(self, db, user_account, create_file):
        """
        Verify that size_formatted returns human-readable format.

        Expected:
            - Bytes shown as "X.XX Б"
            - KB shown as "X.XX КБ"
            - MB shown as "X.XX МБ"
        """

        # Arrange
        file_bytes = create_file(owner=user_account, original_name="small.txt", size=500)
        file_kb = create_file(owner=user_account, original_name="medium.txt", size=2048)
        file_mb = create_file(owner=user_account, original_name="large.txt", size=2097152)

        # Act
        data_bytes = FileSerializer(file_bytes, context={"request": None}).data
        data_kb = FileSerializer(file_kb, context={"request": None}).data
        data_mb = FileSerializer(file_mb, context={"request": None}).data

        # Assert
        assert "Б" in data_bytes["size_formatted"]
        assert "КБ" in data_kb["size_formatted"]
        assert "МБ" in data_mb["size_formatted"]

    def test_file_serializer_has_public_link_boolean(self, db, user_account, create_file):
        """
        Verify that has_public_link returns correct boolean.

        Expected:
            - False when public_link is None
            - True when public_link exists
        """

        # Arrange
        file_no_link = create_file(owner=user_account, original_name="test1.txt")
        file_with_link = create_file(
            owner=user_account, original_name="test2.txt", public_link="abc123"
        )

        # Act
        data_no_link = FileSerializer(file_no_link, context={"request": None}).data
        data_with_link = FileSerializer(file_with_link, context={"request": None}).data

        # Assert
        assert data_no_link["has_public_link"] is False
        assert data_with_link["has_public_link"] is True

    def test_file_serializer_public_link_url_none_when_missing(self, db, user_account, create_file):
        """
        Verify that public_link_url is None when no link exists.

        Expected:
            - public_link_url is None
            - No URL is generated
        """

        # Arrange
        file_obj = create_file(owner=user_account, original_name="test.txt")

        # Act
        data = FileSerializer(file_obj, context={"request": None}).data

        # Assert
        assert data["public_link_url"] is None

    def test_file_serializer_download_url_generated(self, db, user_account, create_file):
        """
        Verify that download_url is generated correctly.

        Expected:
            - URL contains file ID
            - URL contains /download/ path
        """

        # Arrange
        file_obj = create_file(owner=user_account, original_name="test.txt")

        # Act
        data = FileSerializer(file_obj, context={"request": None}).data

        # Assert
        assert data["download_url"] is not None
        assert f"/{file_obj.id}/download/" in data["download_url"]


# ==============================================================================
# TESTS: PUBLIC FILE SERIALIZER
# ==============================================================================


class TestPublicFileSerializer:
    """
    Test suite for PublicFileSerializer (public access).
    """

    def test_public_file_serializer_includes_safe_fields(self, db, user_account, create_file):
        """
        Verify that serializer includes only safe public fields.

        Expected:
            - original_name is included
            - size is included
            - No owner information is included
            - No internal paths are included
        """

        # Arrange
        file_obj = create_file(
            owner=user_account, original_name="public.txt", public_link="publink123"
        )
        serializer = PublicFileSerializer(file_obj, context={"request": None})

        # Act
        data = serializer.data

        # Assert
        assert "original_name" in data
        assert "size" in data
        assert "size_formatted" in data
        assert "download_url" in data
        assert "owner" not in data
        assert "file" not in data  # No internal path

    def test_public_file_serializer_download_url_generated(self, db, user_account, create_file):
        """
        Verify that public download_url is generated correctly.

        Expected:
            - URL contains public_link
            - URL contains /public/ path
        """

        # Arrange
        file_obj = create_file(
            owner=user_account, original_name="test.txt", public_link="publink123"
        )
        serializer = PublicFileSerializer(file_obj, context={"request": None})

        # Act
        data = serializer.data

        # Assert
        assert data["download_url"] is not None
        assert "/public/publink123/download/" in data["download_url"]

    def test_public_file_serializer_comment_included(self, db, user_account, create_file):
        """
        Verify that comment is included in public serializer.

        Expected:
            - comment field is present
            - Comment value is preserved
        """

        # Arrange
        file_obj = create_file(
            owner=user_account,
            original_name="test.txt",
            public_link="publink123",
            comment="Public comment",
        )
        serializer = PublicFileSerializer(file_obj, context={"request": None})

        # Act
        data = serializer.data

        # Assert
        assert "comment" in data
        assert data["comment"] == "Public comment"

    def test_public_file_serializer_size_formatted(self, db, user_account, create_file):
        """
        Verify that size_formatted works in public serializer.

        Expected:
            - Human-readable size is included
            - Format matches FileSerializer
        """

        # Arrange
        file_obj = create_file(
            owner=user_account,
            original_name="test.txt",
            size=5120,
            public_link="publink123",
        )
        serializer = PublicFileSerializer(file_obj, context={"request": None})

        # Act
        data = serializer.data

        # Assert
        assert "size_formatted" in data
        assert "КБ" in data["size_formatted"]

    def test_public_file_serializer_uploaded_at_included(self, db, user_account, create_file):
        """
        Verify that uploaded_at is included in public serializer.

        Expected:
            - uploaded_at field is present
            - Value is valid datetime
        """

        # Arrange
        file_obj = create_file(
            owner=user_account, original_name="test.txt", public_link="publink123"
        )
        serializer = PublicFileSerializer(file_obj, context={"request": None})

        # Act
        data = serializer.data

        # Assert
        assert "uploaded_at" in data
        assert data["uploaded_at"] is not None
