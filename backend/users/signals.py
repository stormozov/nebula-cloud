"""
Signals for user-related events.
"""

import os
import shutil

from django.conf import settings
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from users.models import UserAccount

from .loggers import auth_logger, logger


@receiver(post_save, sender=UserAccount)
def create_user_storage(sender, instance: UserAccount, created: bool, **kwargs) -> None:
    """
    Create storage directory for new user.

    Args:
        sender: The model class (UserAccount)
        instance: The actual instance being saved
        created: Boolean indicating if a new record was created
    """
    if created:
        storage_path = os.path.join(settings.MEDIA_ROOT, "storage", str(instance.pk))

        try:
            os.makedirs(storage_path, exist_ok=True)
            logger.info(
                "Created storage directory for user: user=%s, storage_path=%s",
                instance.username,
                storage_path,
            )
            auth_logger.info(
                "Created storage directory for user: user=%s, storage_path=%s",
                instance.username,
                storage_path,
            )
        except OSError as e:
            logger.error(
                "Error creating storage directory for user: user=%s, storage_path=%s, error=%s",
                instance.username,
                storage_path,
                e,
            )
            auth_logger.error(
                "Error creating storage directory for user: user=%s, storage_path=%s, error=%s",
                instance.username,
                storage_path,
                e,
            )
            raise
        except Exception as e:
            logger.error(
                "Unexpected error creating storage directory for user: \
                    user=%s, storage_path=%s, error=%s",
                instance.username,
                storage_path,
                e,
            )
            raise


@receiver(post_delete, sender=UserAccount)
def delete_user_storage(sender, instance: UserAccount, **kwargs) -> None:
    """
    Delete storage directory for deleted user.

    Args:
        sender: The model class (UserAccount)
        instance: The deleted user instance
    """

    storage_path = os.path.join(settings.MEDIA_ROOT, instance.storage_path)

    try:
        shutil.rmtree(storage_path, ignore_errors=True)
        logger.info(
            "Deleted storage directory for user: user=%s, storage_path=%s",
            instance.username,
            storage_path,
        )
        auth_logger.info(
            "Deleted storage directory for user: user=%s, storage_path=%s",
            instance.username,
            storage_path,
        )
    except Exception as e:
        logger.error(
            "Error deleting storage directory for user: user=%s, storage_path=%s, error=%s",
            instance.username,
            storage_path,
            e,
        )
        auth_logger.error(
            "Error deleting storage directory for user: user=%s, storage_path=%s, error=%s",
            instance.username,
            storage_path,
            e,
        )
