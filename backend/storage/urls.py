"""
URL configuration for storage app.
"""

from django.urls import path

from .views import (
    FileCommentView,
    FileDetailView,
    FileDownloadView,
    FileListView,
    FilePublicLinkView,
    FileRenameView,
    FileUploadView,
    PublicFileDownloadView,
    PublicFileView,
)

urlpatterns = [
    # File management
    path("files/", FileListView.as_view(), name="file-list"),
    path("files/upload/", FileUploadView.as_view(), name="file-upload"),
    path("files/<int:pk>/", FileDetailView.as_view(), name="file-detail"),
    path("files/<int:pk>/rename/", FileRenameView.as_view(), name="file-rename"),
    path("files/<int:pk>/comment/", FileCommentView.as_view(), name="file-comment"),
    path(
        "files/<int:pk>/public-link/generate/",
        FilePublicLinkView.as_view(),
        name="file-public-link-generate",
    ),
    path(
        "files/<int:pk>/public-link/", FilePublicLinkView.as_view(), name="file-public-link-delete"
    ),
    path("files/<int:pk>/download/", FileDownloadView.as_view(), name="file-download"),
    # Public access
    path("public/<str:public_link>/", PublicFileView.as_view(), name="public-file"),
    path(
        "public/<str:public_link>/download/",
        PublicFileDownloadView.as_view(),
        name="public-file-download",
    ),
]
