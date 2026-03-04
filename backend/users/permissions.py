"""
Custom permissions for admin-only endpoints.
"""

from rest_framework import permissions


class IsAdminUser(permissions.BasePermission):
    """
    Custom permission to allow only admin users (is_staff or is_superuser).
    """

    message = "Требуется права администратора для доступа к этому ресурсу."

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_admin_user()

    def has_object_permission(self, request, view, obj):
        return True if request.user.is_admin_user() else obj == request.user
