"""
Permissions for File model operations.
"""

from rest_framework import permissions

from storage.models import File


class IsOwnerOrAdmin(permissions.BasePermission):
    """Check if user is owner or admin."""

    def has_object_permission(self, request, view: object, obj: File) -> bool:
        return True if request.user.is_staff else obj.owner == request.user
