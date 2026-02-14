"""
Signals for user-related events.
"""

import os

from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver

from users.models import UserAccount


@receiver(post_save, sender=UserAccount)
def create_user_storage(sender, instance, created, **kwargs):
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
            print(f"Created storage directory: {storage_path}")
        except Exception as e:
            print(f"Error creating storage directory: {e}")
