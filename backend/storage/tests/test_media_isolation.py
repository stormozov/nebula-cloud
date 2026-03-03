"""
Tests to verify media storage isolation during testing.
"""

import os

from django.conf import settings


class TestMediaIsolation:
    """
    Verify that tests use temporary media directory, not production media.
    """

    def test_media_root_is_temporary(self):
        """
        Verify MEDIA_ROOT points to temporary directory during tests.

        Expected:
            - MEDIA_ROOT contains 'tmp', 'test', or 'pytest' in path
            - MEDIA_ROOT is NOT the production media directory (/media)
        """

        # Arrange
        media_root = settings.MEDIA_ROOT
        is_temporary = (
            "tmp" in media_root.lower()
            or "test" in media_root.lower()
            or "pytest" in media_root.lower()
        )
        is_production = media_root == "/media" or (
            not media_root.startswith("/tmp")
            and not media_root.startswith("/var/tmp")
            and "pytest" not in media_root
            and "test" not in media_root
        )

        # Assert
        # Assert: Check that MEDIA_ROOT is in a temporary/test directory
        assert is_temporary, f"MEDIA_ROOT should be in temporary directory, got: {media_root}"

        # Assert: Check that it's not the production media directory
        assert not is_production, f"MEDIA_ROOT appears to be production directory: {media_root}"

    def test_media_root_is_writable(self):
        """
        Verify temporary media directory is writable.

        Expected:
            - Can create files in MEDIA_ROOT
            - Directory exists
        """

        # Arrange
        media_root = settings.MEDIA_ROOT

        # Assert
        assert os.path.exists(media_root)
        assert os.access(media_root, os.W_OK)
