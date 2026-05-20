"""
Test suite for user signals (post_save / post_delete storage handlers) – fully isolated.
"""

import os
from unittest.mock import MagicMock, patch

import pytest
from django.test.utils import override_settings

from users.models import UserAccount
from ..signals import create_user_storage, delete_user_storage


@pytest.fixture
def mock_user():
    """Return a mock UserAccount instance with minimal attributes."""
    user = MagicMock()
    user.username = "john_doe"
    user.pk = 42
    user.storage_path = "users/john_doe_storage"
    return user


class TestCreateUserStorage:
    """Tests for create_user_storage signal handler."""

    @override_settings(MEDIA_ROOT="/media")
    @patch("users.signals.auth_logger")
    @patch("users.signals.logger")
    @patch("users.signals.os.makedirs")
    def test_created_true_creates_directory_and_logs(
        self, mock_makedirs, mock_logger, mock_auth_logger, mock_user
    ):
        """
        Test that a new user triggers storage directory creation and successful logging.

        Scenario:
            post_save signal is fired with created=True.

        Expected Result:
            - os.makedirs is called with the correct path and exist_ok=True.
            - logger.info and auth_logger.info are called with the expected messages.
        """

        # Arrange
        expected_path = os.path.join("/media", "storage", "42")

        # Act
        create_user_storage(UserAccount, mock_user, created=True)

        # Assert
        mock_makedirs.assert_called_once_with(expected_path, exist_ok=True)
        mock_logger.info.assert_called_once_with(
            "Created storage directory for user: user=%s, storage_path=%s",
            "john_doe",
            expected_path,
        )
        mock_auth_logger.info.assert_called_once_with(
            "Created storage directory for user: user=%s, storage_path=%s",
            "john_doe",
            expected_path,
        )

    @patch("users.signals.auth_logger")
    @patch("users.signals.logger")
    @patch("users.signals.os.makedirs")
    def test_created_false_does_nothing(
        self, mock_makedirs, mock_logger, mock_auth_logger, mock_user
    ):
        """
        Test that post_save with created=False does not create any directory.

        Scenario:
            An existing user is updated (created=False).

        Expected Result:
            - os.makedirs is never called.
            - No log messages are written.
        """

        # Arrange – nothing special

        # Act
        create_user_storage(UserAccount, mock_user, created=False)

        # Assert
        mock_makedirs.assert_not_called()
        mock_logger.info.assert_not_called()
        mock_auth_logger.info.assert_not_called()

    @override_settings(MEDIA_ROOT="/media")
    @patch("users.signals.auth_logger")
    @patch("users.signals.logger")
    @patch("users.signals.os.makedirs")
    def test_os_error_logs_and_raises(
        self, mock_makedirs, mock_logger, mock_auth_logger, mock_user
    ):
        """
        Test that an OSError during directory creation is logged and re-raised.

        Scenario:
            os.makedirs raises OSError.

        Expected Result:
            - logger.error and auth_logger.error are called with the error details.
            - The exception is propagated upwards.
        """

        # Arrange
        error = OSError("Permission denied")
        mock_makedirs.side_effect = error
        expected_path = os.path.join("/media", "storage", "42")

        # Act & Assert
        with pytest.raises(OSError, match="Permission denied"):
            create_user_storage(UserAccount, mock_user, created=True)

        mock_makedirs.assert_called_once()
        mock_logger.error.assert_called_once_with(
            "Error creating storage directory for user: user=%s, storage_path=%s, error=%s",
            "john_doe",
            expected_path,
            error,
        )
        mock_auth_logger.error.assert_called_once_with(
            "Error creating storage directory for user: user=%s, storage_path=%s, error=%s",
            "john_doe",
            expected_path,
            error,
        )


class TestDeleteUserStorage:
    """Tests for delete_user_storage signal handler."""

    @override_settings(MEDIA_ROOT="/media")
    @patch("users.signals.auth_logger")
    @patch("users.signals.logger")
    @patch("users.signals.shutil.rmtree")
    def test_successful_deletion_removes_directory_and_logs(
        self, mock_rmtree, mock_logger, mock_auth_logger, mock_user
    ):
        """
        Test that deleting a user removes their storage directory and logs info.

        Scenario:
            post_delete signal is fired for a user.

        Expected Result:
            - shutil.rmtree is called with the correct path and ignore_errors=True.
            - logger.info and auth_logger.info are called.
        """

        # Arrange
        expected_path = os.path.join("/media", "users/john_doe_storage")

        # Act
        delete_user_storage(UserAccount, mock_user)

        # Assert
        mock_rmtree.assert_called_once_with(expected_path, ignore_errors=True)
        mock_logger.info.assert_called_once_with(
            "Deleted storage directory for user: user=%s, storage_path=%s",
            "john_doe",
            expected_path,
        )
        mock_auth_logger.info.assert_called_once_with(
            "Deleted storage directory for user: user=%s, storage_path=%s",
            "john_doe",
            expected_path,
        )

    @override_settings(MEDIA_ROOT="/media")
    @patch("users.signals.auth_logger")
    @patch("users.signals.logger")
    @patch("users.signals.shutil.rmtree")
    def test_rmtree_error_logs_but_does_not_raise(
        self, mock_rmtree, mock_logger, mock_auth_logger, mock_user
    ):
        """
        Test that an exception during deletion is logged but not propagated.

        Scenario:
            shutil.rmtree raises an Exception.

        Expected Result:
            - logger.error and auth_logger.error are called with the error details.
            - The function completes without raising an exception.
        """

        # Arrange
        error = Exception("Deletion failed")
        mock_rmtree.side_effect = error
        expected_path = os.path.join("/media", "users/john_doe_storage")

        # Act & Assert (no exception expected)
        delete_user_storage(UserAccount, mock_user)

        mock_rmtree.assert_called_once_with(expected_path, ignore_errors=True)
        mock_logger.error.assert_called_once_with(
            "Error deleting storage directory for user: user=%s, storage_path=%s, error=%s",
            "john_doe",
            expected_path,
            error,
        )
        mock_auth_logger.error.assert_called_once_with(
            "Error deleting storage directory for user: user=%s, storage_path=%s, error=%s",
            "john_doe",
            expected_path,
            error,
        )
