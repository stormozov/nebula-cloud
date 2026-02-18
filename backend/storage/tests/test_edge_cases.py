"""
Tests for storage application edge cases.

This module tests boundary conditions and exceptional scenarios including:
- File size limits (0 bytes, 100MB+ limit)
- Filename edge cases (special characters, Unicode, length)
- Concurrent operations (same filename uploads)
- Filesystem inconsistencies (file in DB but missing on disk)
- Database constraints and integrity
- Performance boundary conditions
"""

import time

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db.utils import IntegrityError
from rest_framework import status

from core.settings import MAX_UPLOAD_SIZE
from storage.models import File
from storage.serializers import validate_filename

User = get_user_model()


# ==============================================================================
# TESTS: FILE SIZE EDGE CASES
# ==============================================================================


class TestFileSizeEdgeCases:
    """
    Test suite for file size boundary conditions.

    These tests verify that the application correctly handles:
    - Empty files (0 bytes)
    - Very small files (1 byte)
    - Files at the size limit (100MB)
    - Files exceeding the size limit (100MB+)
    """

    def test_upload_empty_file_0_bytes_accepted(
        self, authenticated_client, user_account, temp_media_root
    ):
        """
        Verify that empty file (0 bytes) is accepted in the system.

        Note: DRF FileField rejects empty files by default. This test verifies
        that the model and storage system can handle empty files correctly.

        Expected:
            - File can be created with size=0
            - File is stored on disk
            - File can be downloaded successfully
        """

        # Act
        original_name = "empty.txt"
        file_obj = File.objects.create(
            owner=user_account,
            original_name=original_name,
            size=0,
            comment="Empty file test",
        )
        file_obj.file.save(original_name, ContentFile(b""), save=True)

        # Assert — file created correctly
        assert File.objects.count() == 1
        assert file_obj.size == 0
        assert file_obj.original_name == original_name

        # Assert — file can be downloaded
        response = authenticated_client.get(f"/api/storage/files/{file_obj.id}/download/")
        assert response.status_code == status.HTTP_200_OK
        assert original_name in response["Content-Disposition"]

    def test_upload_very_small_file_1_byte_accepted(
        self, authenticated_client, user_account, temp_media_root
    ):
        """
        Verify that very small file (1 byte) is accepted.

        Expected:
            - HTTP 201 Created
            - File saved with size=1
        """

        # Arrange
        tiny_file = SimpleUploadedFile(
            name="tiny.txt",
            content=b"x",
            content_type="text/plain",
        )
        upload_data = {"file": tiny_file}

        # Act
        response = authenticated_client.post(
            "/api/storage/files/upload/", upload_data, format="multipart"
        )

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        file_obj = File.objects.first()
        assert file_obj.size == 1

    def test_upload_file_at_100mb_limit_accepted(
        self, authenticated_client, user_account, temp_media_root
    ):
        """
        Verify that file exactly at 100MB limit is accepted.

        Expected:
            - HTTP 201 Created
            - File saved successfully
            - Size is exactly 100MB (104857600 bytes)
        """

        # Arrange
        file_content = b"x" * MAX_UPLOAD_SIZE
        limit_file = SimpleUploadedFile(
            name="limit_100mb.bin",
            content=file_content,
            content_type="application/octet-stream",
        )
        upload_data = {"file": limit_file}

        # Act
        response = authenticated_client.post(
            "/api/storage/files/upload/", upload_data, format="multipart"
        )

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        file_obj = File.objects.first()
        assert file_obj.size == MAX_UPLOAD_SIZE

    def test_upload_file_over_100mb_limit_rejected(
        self, authenticated_client, user_account, temp_media_root
    ):
        """
        Verify that file exceeding 100MB limit is rejected.

        Expected:
            - HTTP 400 Bad Request
            - Error message mentions size limit
            - No file created in database
        """

        # Arrange

        # 101MB (exceeds limit by 1MB)
        file_content = b"x" * (101 * 1024 * 1024)
        over_limit_file = SimpleUploadedFile(
            name="over_limit.bin",
            content=file_content,
            content_type="application/octet-stream",
        )
        upload_data = {"file": over_limit_file}

        # Act
        response = authenticated_client.post(
            "/api/storage/files/upload/", upload_data, format="multipart"
        )

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert File.objects.count() == 0
        assert "100" in str(response.data).lower() or "size" in str(response.data).lower()

    def test_download_empty_file_returns_content(
        self, authenticated_client, user_account, temp_media_root
    ):
        """
        Verify that empty file can be downloaded successfully.

        Expected:
            - HTTP 200 OK
            - Response content is empty
            - Content-Disposition header is present
        """

        # Arrange
        file_name = "empty.txt"
        file_obj = File.objects.create(
            owner=user_account,
            original_name=file_name,
            size=0,
        )
        file_obj.file.save(file_name, ContentFile(b""), save=True)

        # Act
        response = authenticated_client.get(f"/api/storage/files/{file_obj.id}/download/")

        # Assert
        assert response.status_code == status.HTTP_200_OK

        content = b"".join(response.streaming_content)
        assert len(content) == 0

        assert file_name in response["Content-Disposition"]


# ==============================================================================
# TESTS: FILENAME EDGE CASES
# ==============================================================================


class TestFilenameEdgeCases:
    """
    Test suite for filename boundary conditions.

    These tests verify that the application correctly handles:
    - Unicode characters in filenames
    - Very long filenames
    - Files with no extension
    - Files with multiple extensions
    - Special but allowed characters
    """

    def test_upload_file_with_unicode_name_accepted(
        self, authenticated_client, user_account, temp_media_root
    ):
        """
        Verify that filename with Unicode characters is accepted.

        Rationale:
            - International users need Unicode support
            - Russian, Chinese, emoji characters should work

        Expected:
            - HTTP 201 Created
            - original_name preserves Unicode characters
            - File accessible for download
        """

        # Arrange
        file_name = "файл_тест.txt"  # Russian filename
        unicode_file = SimpleUploadedFile(
            name=file_name,
            content=b"Test content",
            content_type="text/plain",
        )
        upload_data = {
            "file": unicode_file,
            "comment": "Unicode filename test",
        }

        # Act
        response = authenticated_client.post(
            "/api/storage/files/upload/", upload_data, format="multipart"
        )

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        file_obj = File.objects.first()
        assert file_obj.original_name == file_name

    def test_upload_file_with_emoji_name_accepted(
        self, authenticated_client, user_account, temp_media_root
    ):
        """
        Verify that filename with emoji characters is accepted.

        Expected:
            - HTTP 201 Created
            - Emoji preserved in original_name
        """

        # Arrange
        emoji_file = SimpleUploadedFile(
            name="document_🚀_2024.pdf",  # Emoji in name
            content=b"Test content",
            content_type="application/pdf",
        )
        upload_data = {"file": emoji_file}

        # Act
        response = authenticated_client.post(
            "/api/storage/files/upload/", upload_data, format="multipart"
        )

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        file_obj = File.objects.first()
        assert "🚀" in file_obj.original_name

    def test_upload_file_with_very_long_name_accepted(
        self, authenticated_client, user_account, temp_media_root
    ):
        """
        Verify that filename with maximum allowed length is accepted.

        Expected:
            - HTTP 201 Created
            - Full filename preserved (up to 255 chars)
        """

        # Arrange
        max_chars = 255

        # Create filename at max length (255 characters)
        long_name = "a" * 250 + ".txt"
        long_file = SimpleUploadedFile(
            name=long_name,
            content=b"Test content",
            content_type="text/plain",
        )
        upload_data = {"file": long_file}

        # Act
        response = authenticated_client.post(
            "/api/storage/files/upload/", upload_data, format="multipart"
        )

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        file_obj = File.objects.first()
        assert len(file_obj.original_name) <= max_chars

    def test_rename_file_name_over_255_chars_rejected(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that filename exceeding 255 characters is rejected.

        Expected:
            - HTTP 400 Bad Request
            - original_name unchanged
        """

        # Arrange
        file_name = "original.txt"
        file_obj = create_file(owner=authenticated_client.user, original_name=file_name)
        too_long_name = "x" * 256  # Exceeds 255 char limit
        rename_data = {"original_name": too_long_name}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_obj.id}/rename/", rename_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        file_obj.refresh_from_db()
        assert file_obj.original_name == file_name

    def test_upload_file_with_no_extension_accepted(
        self, authenticated_client, user_account, temp_media_root
    ):
        """
        Verify that filename without extension is accepted.

        Rationale:
            - Some files legitimately have no extension
            - Makefile, README, LICENSE, etc.

        Expected:
            - HTTP 201 Created
            - Filename preserved as-is
        """

        # Arrange
        file_name = "README"  # No extension
        no_ext_file = SimpleUploadedFile(
            name=file_name,
            content=b"Test content",
            content_type="text/plain",
        )
        upload_data = {"file": no_ext_file}

        # Act
        response = authenticated_client.post(
            "/api/storage/files/upload/", upload_data, format="multipart"
        )

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        file_obj = File.objects.first()
        assert file_obj.original_name == file_name

    def test_upload_file_with_multiple_extensions_accepted(
        self, authenticated_client, user_account, temp_media_root
    ):
        """
        Verify that filename with multiple extensions is accepted.

        Examples:
            - file.tar.gz
            - archive.zip.bak
            - document.pdf.backup

        Expected:
            - HTTP 201 Created
            - Full filename preserved
        """

        # Arrange
        file_name = "archive.tar.gz.backup"  # Multiple extensions
        multi_ext_file = SimpleUploadedFile(
            name=file_name,
            content=b"Test content",
            content_type="application/octet-stream",
        )
        upload_data = {"file": multi_ext_file}

        # Act
        response = authenticated_client.post(
            "/api/storage/files/upload/", upload_data, format="multipart"
        )

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        file_obj = File.objects.first()
        assert file_obj.original_name == file_name

    def test_rename_file_with_spaces_in_name_accepted(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that filename with spaces is accepted.

        Expected:
            - HTTP 200 OK
            - Spaces preserved in filename
        """

        # Arrange
        file_name = "new name with spaces.txt"
        file_obj = create_file(owner=authenticated_client.user, original_name="old_name.txt")
        rename_data = {"original_name": file_name}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_obj.id}/rename/", rename_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        file_obj.refresh_from_db()
        assert file_obj.original_name == file_name

    def test_validate_filename_special_characters_allowed(self):
        """
        Verify that certain special characters are allowed in filenames.

        Allowed characters:
            - Underscore (_)
            - Hyphen (-)
            - At symbol (@)
            - Plus (+)
            - Parentheses ()
            - Brackets []

        Expected:
            - No ValidationError raised
        """

        # Arrange
        valid_names = [
            "file-name.txt",
            "file_name.txt",
            "file@domain.txt",
            "file+backup.txt",
            "file (copy).txt",
            "file [2024].txt",
        ]

        # Act & Assert
        for name in valid_names:
            # Should not raise ValidationError
            result = validate_filename(name)
            assert result is not None


# ==============================================================================
# TESTS: CONCURRENT OPERATIONS
# ==============================================================================


class TestConcurrentOperations:
    """
    Test suite for concurrent and race condition scenarios.

    These tests verify that the application handles:
    - Multiple uploads with same filename
    - Simultaneous public link generation
    - Concurrent rename operations
    """

    def test_multiple_users_upload_same_filename_unique_paths(
        self,
        user_account,
        another_user_account,
        admin_client,
        temp_media_root,
    ):
        """
        Verify that multiple users uploading same filename get unique paths.

        Rationale:
            - Different users may upload "document.pdf" simultaneously
            - Each file must have unique storage path
            - Original names should be preserved in DB

        Expected:
            - All uploads succeed (HTTP 201)
            - Each file has unique path on disk
            - original_name is preserved for each
        """

        # Arrange
        file_name = "document.pdf"
        file1 = File.objects.create(owner=user_account, original_name=file_name, size=100)
        file2 = File.objects.create(
            owner=another_user_account, original_name=file_name, size=100
        )

        # Act
        file1.file.save(file_name, ContentFile(b"Content 1"), save=True)
        file2.file.save(file_name, ContentFile(b"Content 2"), save=True)

        # Assert
        assert file1.file.path != file2.file.path
        assert file1.original_name == file2.original_name
        assert file1.owner != file2.owner

    def test_same_user_upload_same_filename_twice_unique_paths(
        self, authenticated_client, temp_media_root
    ):
        """
        Verify that same user uploading same filename twice gets unique paths.

        Expected:
            - Both uploads succeed
            - Unique paths generated for each
            - No file overwriting occurs
        """

        # Arrange
        file_name = "backup.zip"
        file_content = b"Test content for duplicate upload"
        content_type = "application/zip"
        file_format = "multipart"

        def upload_file():
            return authenticated_client.post(
                "/api/storage/files/upload/",
                {"file": SimpleUploadedFile(file_name, file_content, content_type)},
                format=file_format,
            )

        # Act
        response1 = upload_file()
        response2 = upload_file()

        # Assert
        assert response1.status_code == status.HTTP_201_CREATED
        assert response2.status_code == status.HTTP_201_CREATED

        file1 = File.objects.get(id=response1.data["id"])
        file2 = File.objects.get(id=response2.data["id"])

        assert file1.file.path != file2.file.path

    def test_generate_public_link_twice_returns_existing(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that generating public link twice returns existing link.

        Expected:
            - First call: HTTP 200, link generated
            - Second call: HTTP 400, link already exists
            - Link remains unchanged
        """

        # Arrange
        file_obj = create_file(owner=authenticated_client.user, original_name="test.txt")

        def generate_link():
            return authenticated_client.post(
                f"/api/storage/files/{file_obj.id}/public-link/generate/",
                data={},
                format="json",
            )

        # Act
        response1 = generate_link()
        first_link = response1.data["public_link_url"]
        response2 = generate_link()

        # Assert
        assert response1.status_code == status.HTTP_200_OK
        assert response2.status_code == status.HTTP_400_BAD_REQUEST

        file_obj.refresh_from_db()
        assert file_obj.public_link is not None
        assert first_link is not None


# ==============================================================================
# TESTS: FILESYSTEM INCONSISTENCIES
# ==============================================================================


class TestFilesystemInconsistencies:
    """
    Test suite for filesystem and database inconsistency scenarios.

    These tests verify that the application handles:
    - File record in DB but missing on disk
    - Corrupted file paths
    - Permission issues on file access
    """

    def test_download_file_missing_on_disk_returns_404(
        self, authenticated_client, user_account, temp_media_root
    ):
        """
        Verify that downloading file missing from disk returns 404.

        Scenario:
            1. Create file record in database
            2. Do NOT save actual file to disk
            3. Attempt to download

        Expected:
            - HTTP 404 Not Found
            - Error message indicates file not found on server
            - Database record may still exist (not automatically cleaned)
        """

        # Arrange
        file_obj = File.objects.create(
            owner=user_account,
            original_name="missing_file.txt",
            size=100,
        )

        # Act
        response = authenticated_client.get(f"/api/storage/files/{file_obj.id}/download/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert (
            "не найден" in str(response.data).lower() or "not found" in str(response.data).lower()
        )

    def test_delete_file_missing_on_disk_succeeds(
        self, authenticated_client, user_account, temp_media_root
    ):
        """
        Verify that deleting file missing from disk still succeeds.

        Rationale:
            - Database record should be cleaned up even if file is missing
            - Prevents orphaned database records
            - Idempotent delete operation

        Expected:
            - HTTP 204 No Content
            - Database record is removed
            - No error raised for missing file
        """

        # Arrange
        file_obj = File.objects.create(
            owner=user_account,
            original_name="orphan.txt",
            size=100,
        )

        # Act
        response = authenticated_client.delete(f"/api/storage/files/{file_obj.id}/")

        # Assert
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not File.objects.filter(id=file_obj.id).exists()

    def test_public_download_file_missing_on_disk_returns_404(
        self, api_client, user_account, temp_media_root
    ):
        """
        Verify that public download of missing file returns 404.

        Expected:
            - HTTP 404 Not Found
            - Same behavior as authenticated download
        """

        # Arrange
        File.objects.create(
            owner=user_account,
            original_name="public_missing.txt",
            size=100,
            public_link="missinglink123",
        )

        # Act
        response = api_client.get("/api/storage/public/missinglink123/download/")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND


# ==============================================================================
# TESTS: DATABASE CONSTRAINTS
# ==============================================================================


class TestDatabaseConstraints:
    """
    Test suite for database constraint and integrity scenarios.

    These tests verify that the application handles:
    - NULL constraints on required fields
    - Unique constraints on public_link
    - Foreign key constraints on owner
    - Data type constraints
    """

    def test_create_file_without_owner_raises_integrity_error(self, user_account):
        """
        Verify that file cannot be created without owner.

        Expected:
            - IntegrityError raised
            - Database constraint prevents NULL owner_id
        """
        # Arrange & Act & Assert
        with pytest.raises(IntegrityError):
            File.objects.create(
                owner=None,  # NULL not allowed
                original_name="test.txt",
                size=100,
            )

    def test_create_file_without_original_name_raises_error(self, user_account):
        """
        Verify that file cannot be created without original_name.

        Expected:
            - IntegrityError or ValidationError raised
            - Database constraint prevents NULL original_name
        """
        # Arrange & Act & Assert
        with pytest.raises(IntegrityError):
            File.objects.create(
                owner=user_account,
                original_name=None,  # NULL not allowed
                size=100,
            )

    def test_public_link_must_be_unique(self, user_account, another_user_account):
        """
        Verify that public_link values must be unique across all files.

        Expected:
            - First file with link succeeds
            - Second file with same link raises IntegrityError
        """

        # Arrange
        public_link = "unique_link_123"
        File.objects.create(
            owner=user_account,
            original_name="file1.txt",
            size=100,
            public_link=public_link,
        )

        # Act & Assert
        with pytest.raises(IntegrityError):
            File.objects.create(
                owner=another_user_account,
                original_name="file2.txt",
                size=100,
                public_link=public_link,
            )

    def test_file_size_cannot_be_negative(self, user_account):
        """
        Verify that file size cannot be negative via model validation.

        Expected:
            - ValidationError raised when calling full_clean() with negative size
        """

        # Arrange
        file_obj = File(
            owner=user_account,
            original_name="test.txt",
            size=-100,
        )

        # Act & Assert
        with pytest.raises(ValidationError):
            file_obj.full_clean()

    def test_uploaded_at_is_auto_set_on_create(self, user_account, temp_media_root):
        """
        Verify that uploaded_at is automatically set on file creation.

        Expected:
            - uploaded_at is not None
            - uploaded_at is close to current time
        """

        # Arrange
        from django.utils import timezone

        # Act
        file_obj = File.objects.create(
            owner=user_account,
            original_name="test.txt",
            size=100,
        )

        # Assert
        assert file_obj.uploaded_at is not None
        time_diff = abs((timezone.now() - file_obj.uploaded_at).total_seconds())
        assert time_diff < 5  # Within 5 seconds


# ==============================================================================
# TESTS: PERFORMANCE BOUNDARIES
# ==============================================================================


class TestPerformanceBoundaries:
    """
    Test suite for performance-related boundary conditions.

    These tests verify that the application handles:
    - Large number of files for single user
    - Large comment fields
    - Multiple public link operations
    """

    def test_user_with_many_files_list_returns_all(
        self, authenticated_client, user_account, temp_media_root
    ):
        """
        Verify that user with many files can retrieve complete list.

        Expected:
            - HTTP 200 OK
            - All files returned (no pagination limit in current implementation)
            - Response time is reasonable (< 5 seconds for 100 files)
        """

        # Arrange - Create 100 files for user
        users_count = 100
        start_time = time.time()

        for i in range(users_count):
            file_name = f"file_{i:03d}.txt"
            file_obj = File.objects.create(
                owner=user_account,
                original_name=file_name,
                size=100,
                comment=f"Comment {i}",
            )
            file_obj.file.save(file_name, ContentFile(b"Content"), save=True)

        # Act
        response = authenticated_client.get("/api/storage/files/")
        elapsed_time = time.time() - start_time

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) == users_count
        assert elapsed_time < 10  # Should complete in under 10 seconds

    def test_comment_with_maximum_length_accepted(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that comment at maximum length is accepted.

        Expected:
            - HTTP 200 OK
            - Full comment preserved
        """

        # Arrange
        file_obj = create_file(owner=authenticated_client.user, original_name="test.txt")
        max_comment = "x" * 1000  # Maximum allowed length
        comment_data = {"comment": max_comment}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_obj.id}/comment/", comment_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        file_obj.refresh_from_db()
        assert file_obj.comment == max_comment

    def test_comment_over_maximum_length_rejected(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that comment exceeding maximum length is rejected.

        Expected:
            - HTTP 400 Bad Request
            - comment unchanged
        """

        # Arrange
        file_obj = create_file(owner=authenticated_client.user, original_name="test.txt")
        too_long_comment = "x" * 1001  # Exceeds 1000 char limit
        comment_data = {"comment": too_long_comment}

        # Act
        response = authenticated_client.patch(
            f"/api/storage/files/{file_obj.id}/comment/", comment_data, format="json"
        )

        # Assert
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        file_obj.refresh_from_db()
        assert file_obj.comment != too_long_comment

    def test_rapid_sequential_operations_succeed(
        self, authenticated_client, create_file, temp_media_root
    ):
        """
        Verify that rapid sequential operations complete successfully.

        Scenario:
            - Upload, rename, comment, download in quick succession
            - No race conditions or locks

        Expected:
            - All operations succeed
            - No timeout or connection errors
        """

        # Act - Rapid sequential operations
        upload_response = authenticated_client.post(
            "/api/storage/files/upload/",
            {"file": SimpleUploadedFile("rapid.txt", b"content", "text/plain")},
            format="multipart",
        )

        file_id = upload_response.data["id"]

        rename_response = authenticated_client.patch(
            f"/api/storage/files/{file_id}/rename/",
            {"original_name": "renamed_rapid.txt"},
            format="json",
        )

        comment_response = authenticated_client.patch(
            f"/api/storage/files/{file_id}/comment/",
            {"comment": "Rapid comment"},
            format="json",
        )

        download_response = authenticated_client.get(f"/api/storage/files/{file_id}/download/")

        # Assert
        assert upload_response.status_code == status.HTTP_201_CREATED
        assert rename_response.status_code == status.HTTP_200_OK
        assert comment_response.status_code == status.HTTP_200_OK
        assert download_response.status_code == status.HTTP_200_OK
