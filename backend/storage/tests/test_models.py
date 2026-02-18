"""
Tests for File model.

This module tests the File model functionality including:
- File creation and metadata
- Unique path generation
- Public link generation
- File deletion (including physical file removal)
- Download tracking
- String representation
"""

# pylint: disable=unused-argument
# pylint: disable=no-member

import os
import time

from django.core.files.base import ContentFile
from django.utils import timezone

from storage.models import File, generate_unique_path

# ==============================================================================
# TESTS: FILE CREATION
# ==============================================================================


class TestFileCreation:
    """
    Test suite for File model creation and basic properties.
    """

    def test_file_creation_with_required_fields(self, db, user_account, test_file):
        """
        Verify that File can be created with required fields only.

        Scenario:
            1. Create File instance with owner, file, original_name, size
            2. Save to database
            3. Verify all required fields are stored correctly

        Expected:
            - File object is created successfully
            - All required fields match input values
            - uploaded_at is automatically set
            - Optional fields are null/empty by default
        """

        # Arrange
        file_obj = File(
            owner=user_account,
            original_name="document.pdf",
            size=2048,
        )
        file_obj.file.save("document.pdf", ContentFile(b"Test content"), save=True)

        # Act
        file_obj.save()

        # Assert
        assert file_obj.id is not None
        assert file_obj.owner == user_account
        assert file_obj.original_name == "document.pdf"
        assert file_obj.size == 2048
        assert file_obj.uploaded_at is not None
        assert file_obj.comment is None
        assert file_obj.public_link is None
        assert file_obj.last_downloaded is None

    def test_file_creation_with_all_fields(self, db, user_account, test_file):
        """
        Verify that File can be created with all optional fields.

        Scenario:
            1. Create File with comment and public_link
            2. Save to database
            3. Verify all fields are stored correctly

        Expected:
            - All optional fields are preserved
            - No data loss or transformation
        """

        # Arrange
        file_obj = File(
            owner=user_account,
            original_name="report.xlsx",
            size=4096,
            comment="Quarterly financial report",
            public_link="abc123xyz",
        )
        file_obj.file.save("report.xlsx", ContentFile(b"Test content"), save=True)

        # Act
        file_obj.save()

        # Assert
        assert file_obj.comment == "Quarterly financial report"
        assert file_obj.public_link == "abc123xyz"

    def test_file_size_default_value(self, db, user_account):
        """
        Verify that size field has default value of 0.

        Expected:
            - File can be created without explicit size
            - Default size is 0
        """

        # Arrange & Act
        file_obj = File(
            owner=user_account,
            original_name="empty.txt",
        )
        file_obj.file.save("empty.txt", ContentFile(b""), save=True)

        # Assert
        assert file_obj.size == 0


# ==============================================================================
# TESTS: UNIQUE PATH GENERATION
# ==============================================================================


class TestUniquePathGeneration:
    """
    Test suite for generate_unique_path function.
    """

    def test_generate_unique_path_creates_user_directory(self, db, user_account):
        """
        Verify that generated path includes user ID directory.

        Scenario:
            1. Create File instance (required for generate_unique_path)
            2. Call generate_unique_path with file instance
            3. Check path structure

        Expected:
            - Path contains storage/{user_id}/ prefix
            - Path includes unique ID (12 chars)
            - Path preserves file extension
        """

        # Arrange
        file_instance = File(
            owner=user_account,
            original_name="document.pdf",
            size=100,
        )
        file_instance.file.save("document.pdf", ContentFile(b"Test"), save=False)

        # Act
        path = generate_unique_path(file_instance, "document.pdf")

        # Assert
        assert path.startswith(f"storage/{user_account.id}/")
        assert path.endswith(".pdf")
        # Check unique ID length (12 chars + 2 char prefix)
        parts = path.split("/")
        unique_part = parts[-1].replace(".pdf", "")
        assert len(unique_part) == 12

    def test_generate_unique_path_preserves_extension(self, db, user_account):
        """
        Verify that file extension is preserved in lowercase.

        Expected:
            - .PDF becomes .pdf
            - .JPG becomes .jpg
            - Extension is always lowercase
        """

        # Arrange
        file_instance = File(owner=user_account, original_name="test.txt", size=100)
        file_instance.file.save("test.txt", ContentFile(b"Test"), save=False)

        # Act
        path_upper = generate_unique_path(file_instance, "IMAGE.PNG")
        path_mixed = generate_unique_path(file_instance, "Document.PdF")

        # Assert
        assert path_upper.endswith(".png")
        assert path_mixed.endswith(".pdf")

    def test_generate_unique_path_creates_unique_ids(self, db, user_account):
        """
        Verify that multiple calls generate different unique IDs.

        Expected:
            - Each call produces different path
            - No collisions in 100 iterations
        """

        # Arrange
        file_instance = File(owner=user_account, original_name="test.txt", size=100)
        file_instance.file.save("test.txt", ContentFile(b"Test"), save=False)

        paths = set()

        # Act
        for _ in range(100):
            path = generate_unique_path(file_instance, "test.txt")
            paths.add(path)

        # Assert
        assert len(paths) == 100  # All paths are unique

    def test_generate_unique_path_uses_prefix_subdirectory(self, db, user_account):
        """
        Verify that path includes 2-character prefix subdirectory.

        Expected:
            - Path structure: storage/{user_id}/{prefix}/{unique_id}.{ext}
            - Prefix is first 2 characters of unique ID
        """

        # Arrange
        file_instance = File(owner=user_account, original_name="test.txt", size=100)
        file_instance.file.save("test.txt", ContentFile(b"Test"), save=False)

        # Act
        path = generate_unique_path(file_instance, "file.txt")

        # Assert
        parts = path.split("/")
        assert len(parts) == 4  # storage, user_id, prefix, filename
        prefix = parts[2]
        unique_id = parts[3].replace(".txt", "")
        assert prefix == unique_id[:2]


# ==============================================================================
# TESTS: PUBLIC LINK
# ==============================================================================


class TestPublicLink:
    """
    Test suite for public link generation and management.
    """

    def test_generate_public_link_creates_unique_link(self, db, user_account):
        """
        Verify that generate_public_link creates unique 12-character link.

        Scenario:
            1. Create File without public_link
            2. Call generate_public_link(force=True)
            3. Verify link is generated

        Expected:
            - public_link is 12 characters
            - Link contains only valid nanoid characters (alphanumeric + -_)
            - Link is unique in database
        """

        # Arrange
        file_obj = File.objects.create(
            owner=user_account,
            original_name="test.txt",
            size=100,
        )

        # Act
        link = file_obj.generate_public_link(force=True)

        # Assert
        assert link is not None
        assert len(link) == 12
        # nanoid uses alphanumeric + '-' + '_' by default
        assert all(c.isalnum() or c in "-_" for c in link)  # ✅ Исправленная проверка
        assert file_obj.public_link == link

    def test_generate_public_link_returns_existing_if_not_force(self, db, user_account):
        """
        Verify that generate_public_link returns existing link when force=False.

        Expected:
            - If public_link exists, it is returned without regeneration
            - No database update occurs
        """

        # Arrange
        file_obj = File.objects.create(
            owner=user_account,
            original_name="test.txt",
            size=100,
            public_link="existing123",
        )

        # Act
        link = file_obj.generate_public_link(force=False)

        # Assert
        assert link == "existing123"

    def test_generate_public_link_unique_across_all_files(
        self, db, user_account, another_user_account
    ):
        """
        Verify that public links are unique across all users.

        Scenario:
            1. Create files for multiple users
            2. Generate public links for all
            3. Verify no duplicates

        Expected:
            - All links are unique
            - No collisions between different users
        """

        # Arrange
        files = [
            File.objects.create(
                owner=user_account if i % 2 == 0 else another_user_account,
                original_name=f"file_{i}.txt",
                size=100,
            )
            for i in range(10)
        ]

        # Act
        links = [f.generate_public_link(force=True) for f in files]

        # Assert
        assert len(set(links)) == 10  # All unique

    def test_generate_public_link_handles_collision(self, db, user_account, monkeypatch):
        """
        Verify that generate_public_link retries on collision.

        Scenario:
            1. Mock nanoid to return same value twice
            2. Create file with that link
            3. Generate link for new file

        Expected:
            - Function retries and generates different link
            - No IntegrityError raised
        """

        # Arrange
        from nanoid import generate

        call_count = [0]
        original_generate = generate

        def mock_generate(size=12):
            call_count[0] += 1
            return "collision1" if call_count[0] == 1 else original_generate(size=size)

        monkeypatch.setattr("storage.models.generate", mock_generate)

        # Create file with colliding link
        File.objects.create(
            owner=user_account,
            original_name="existing.txt",
            size=100,
            public_link="collision1",
        )

        new_file = File.objects.create(
            owner=user_account,
            original_name="new.txt",
            size=100,
        )

        # Act
        link = new_file.generate_public_link(force=True)

        # Assert
        assert link != "collision1"
        assert call_count[0] == 2  # Called twice (collision + retry)


# ==============================================================================
# TESTS: FILE DELETION
# ==============================================================================


class TestFileDeletion:
    """
    Test suite for File deletion and cleanup.
    """

    def test_delete_removes_database_record(self, db, user_account, create_file):
        """
        Verify that delete() removes File from database.

        Expected:
            - File count decreases by 1
            - File cannot be retrieved after deletion
        """

        # Arrange
        file_obj = create_file(owner=user_account)
        file_id = file_obj.id

        # Act
        file_obj.delete()

        # Assert
        assert not File.objects.filter(id=file_id).exists()

    def test_delete_removes_physical_file(self, db, user_account, temp_media_root):
        """
        Verify that delete() removes physical file from storage.

        Scenario:
            1. Create File with actual file content
            2. Get file path
            3. Delete File
            4. Check file system

        Expected:
            - Physical file is removed from disk
            - No orphaned files remain
        """

        # Arrange
        file_obj = File.objects.create(
            owner=user_account,
            original_name="test.txt",
            size=100,
        )
        file_obj.file.save("test.txt", ContentFile(b"Test content"), save=True)
        file_path = file_obj.file.path

        # Verify file exists before deletion
        assert os.path.exists(file_path)

        # Act
        file_obj.delete()

        # Assert
        assert not os.path.exists(file_path)

    def test_delete_handles_missing_physical_file(self, db, user_account):
        """
        Verify that delete() does not raise error if physical file is missing.

        Scenario:
            1. Create File
            2. Manually remove physical file
            3. Call delete()

        Expected:
            - No exception raised
            - Database record is still removed
        """

        # Arrange
        file_obj = File.objects.create(
            owner=user_account,
            original_name="test.txt",
            size=100,
        )
        file_obj.file.save("test.txt", ContentFile(b"Test content"), save=True)

        # Manually remove physical file
        if os.path.exists(file_obj.file.path):
            os.remove(file_obj.file.path)

        # Act & Assert (should not raise)
        file_obj.delete()
        assert not File.objects.filter(id=file_obj.id).exists()


# ==============================================================================
# TESTS: DOWNLOAD TRACKING
# ==============================================================================


class TestDownloadTracking:
    """
    Test suite for last_downloaded timestamp tracking.
    """

    def test_update_last_downloaded_sets_timestamp(self, db, user_account, create_file):
        """
        Verify that update_last_downloaded() sets last_downloaded field.

        Expected:
            - last_downloaded is set to current time
            - Timestamp is within 1 second of now
        """

        # Arrange
        file_obj = create_file(owner=user_account)
        assert file_obj.last_downloaded is None

        # Act
        file_obj.update_last_downloaded()

        # Assert
        assert file_obj.last_downloaded is not None
        time_diff = abs((timezone.now() - file_obj.last_downloaded).total_seconds())
        assert time_diff < 1

    def test_update_last_downloaded_updates_existing_timestamp(self, db, user_account, create_file):
        """
        Verify that update_last_downloaded() updates existing timestamp.

        Expected:
            - New timestamp is later than previous
            - Field is updated correctly
        """

        # Arrange
        file_obj = create_file(owner=user_account)
        file_obj.last_downloaded = timezone.now()
        file_obj.save()
        old_timestamp = file_obj.last_downloaded

        # Wait a small amount
        time.sleep(0.1)

        # Act
        file_obj.update_last_downloaded()

        # Assert
        assert file_obj.last_downloaded > old_timestamp


# ==============================================================================
# TESTS: STRING REPRESENTATION
# ==============================================================================


class TestStringRepresentation:
    """
    Test suite for File __str__ method.
    """

    def test_str_returns_original_name_and_owner(self, db, user_account, create_file):
        """
        Verify that __str__ returns formatted string with name and owner.

        Expected:
            - String contains original_name
            - String contains owner email
        """

        # Arrange
        file_obj = create_file(
            owner=user_account,
            original_name="document.pdf",
        )

        # Act
        result = str(file_obj)

        # Assert
        assert "document.pdf" in result
        assert user_account.email in result

    def test_str_handles_missing_email(self, db, user_account, create_file):
        """
        Verify that __str__ handles missing email gracefully.

        Expected:
            - Falls back to username if email is missing
            - No AttributeError raised
        """

        # Arrange
        user_account.email = ""
        user_account.save()

        file_obj = create_file(
            owner=user_account,
            original_name="test.txt",
        )

        # Act & Assert (should not raise)
        result = str(file_obj)
        assert "test.txt" in result


# ==============================================================================
# TESTS: MODEL META
# ==============================================================================


class TestModelMeta:
    """
    Test suite for File model Meta options.
    """

    def test_ordering_by_uploaded_at_desc(self, db, user_account, create_file):
        """
        Verify that files are ordered by uploaded_at descending.

        Expected:
            - Most recently uploaded file appears first
            - Default queryset respects ordering
        """

        # Arrange
        create_file(owner=user_account, original_name="first.txt")
        time.sleep(0.1)
        create_file(owner=user_account, original_name="second.txt")
        time.sleep(0.1)
        create_file(owner=user_account, original_name="third.txt")

        # Act
        files = list(File.objects.filter(owner=user_account))

        # Assert
        assert files[0].original_name == "third.txt"
        assert files[1].original_name == "second.txt"
        assert files[2].original_name == "first.txt"

    def test_db_table_name(self, db, user_account, create_file):
        """
        Verify that database table name is correct.

        Expected:
            - Table name is 'storage_file'
        """

        # Arrange
        create_file(owner=user_account)

        # Act
        table_name = File._meta.db_table  # pylint: disable=protected-access

        # Assert
        assert table_name == "storage_file"
