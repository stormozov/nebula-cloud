"""
Global pytest fixtures for the project.
"""

import shutil
import tempfile

import pytest
from django.conf import settings
from django.core.files.storage import default_storage


@pytest.fixture(scope="session")
def django_db_setup():
    """
    Ensure test database is created and cleaned up properly.
    """


@pytest.fixture(autouse=True)
def temp_media_root():
    """
    Automatically apply temporary media directory to ALL tests.
    This fixture runs before every test and cleans up after.

    Yields:
        str: Path to temporary media directory.
    """

    original_media_root = settings.MEDIA_ROOT
    temp_dir = tempfile.mkdtemp(prefix="pytest_media_")
    settings.MEDIA_ROOT = temp_dir

    original_location = default_storage.location
    default_storage.location = temp_dir

    yield temp_dir

    # Cleanup
    settings.MEDIA_ROOT = original_media_root
    default_storage.location = original_location
    shutil.rmtree(temp_dir, ignore_errors=True)
