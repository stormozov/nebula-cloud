"""
Utils for storage app.
"""

import os

from nanoid import generate


def generate_unique_path(instance: object, filename: str) -> str:
    """Generate unique path for file: `storage/{user_id}/{prefix}/{unique_id}{ext}`"""

    user_id = instance.owner.id
    ext = os.path.splitext(filename)[1].lower()
    unique_id = generate(size=12)
    prefix = unique_id[:2]

    return f"storage/{user_id}/{prefix}/{unique_id}{ext}"
