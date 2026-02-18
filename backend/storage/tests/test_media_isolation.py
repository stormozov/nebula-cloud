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
            - MEDIA_ROOT contains 'tmp' or 'test' in path
            - MEDIA_ROOT is NOT the production media directory
        """
        # Assert
        assert "tmp" in settings.MEDIA_ROOT.lower() or "test" in settings.MEDIA_ROOT.lower()
        assert not settings.MEDIA_ROOT.endswith("/media")  # Not production

    def test_media_root_is_writable(self):
        """
        Verify temporary media directory is writable.

        Expected:
            - Can create files in MEDIA_ROOT
            - Directory exists
        """
        # Assert
        assert os.path.exists(settings.MEDIA_ROOT)
        assert os.access(settings.MEDIA_ROOT, os.W_OK)

    def test_media_root_is_unique_per_test_run(self):
        """
        Verify each test run gets unique media directory.

        Expected:
            - Directory name contains random component
        """
        # Assert
        assert len(os.path.basename(settings.MEDIA_ROOT)) > 10  # Has random suffix
