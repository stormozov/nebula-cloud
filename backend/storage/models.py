"""
Models for storage app.
"""

from django.core.validators import MinValueValidator
from django.db import IntegrityError, models, transaction
from django.utils import timezone
from nanoid import generate

from core.settings import AUTH_USER_MODEL
from core.utils import PUBLIC_URL_LEN
from storage.utils import generate_unique_path
from storage.loggers import file_logger


class File(models.Model):
    """A model for storing user files."""

    owner = models.ForeignKey(AUTH_USER_MODEL, related_name="files", on_delete=models.CASCADE)

    file = models.FileField(
        verbose_name="Физический файл с уникальным именем",
        upload_to=generate_unique_path,
        max_length=255,
        validators=[
            MinValueValidator(0),
        ],
    )

    original_name = models.CharField(verbose_name="Оригинальное имя", max_length=255)

    size = models.BigIntegerField(verbose_name="Размер файла в байтах", default=0)

    uploaded_at = models.DateTimeField(verbose_name="Дата и время загрузки", auto_now_add=True)

    last_downloaded = models.DateTimeField(
        verbose_name="Дата последнего скачивания", null=True, blank=True
    )

    comment = models.TextField(verbose_name="Комментарии к файлу", null=True, blank=True)

    public_link = models.CharField(
        verbose_name="Ключ публичной ссылки", unique=True, null=True, blank=True, max_length=50
    )

    def __str__(self) -> str:
        owner_username = getattr(self.owner, "username", "unknown")
        owner_ident = getattr(self.owner, "email", owner_username)
        return f"{self.original_name} (Владелец: {owner_ident})"

    class Meta:
        """Settings for File model."""

        verbose_name = "Файл"
        verbose_name_plural = "Файлы"
        ordering = ["-uploaded_at"]
        db_table = "storage_file"
        app_label = "storage"

        indexes = [
            models.Index(fields=["owner", "-uploaded_at"]),
            models.Index(fields=["public_link"]),
        ]

    def update_last_downloaded(self) -> None:
        """Update last_downloaded field."""
        self.last_downloaded = timezone.now()
        self.save(update_fields=["last_downloaded"])

    def delete(self, *args, **kwargs):
        if self.file:
            self.file.delete(save=False)  # type: ignore[attr-defined] pylint: disable=no-member
        super().delete(*args, **kwargs)

    def generate_public_link(self, force: bool = False, max_retries: int = 10) -> str:
        """
        Generate a new public link with collision handling.

        Args:
            force: If True, replace existing link.
            max_retries: Maximum number of retry attempts on collision.

        Returns:
            str: Generated public link string.
        """

        if self.public_link and not force:
            return self.public_link

        for attempt in range(max_retries):
            try:
                self.public_link = generate(size=PUBLIC_URL_LEN)

                with transaction.atomic():
                    self.save(update_fields=["public_link"])

                return self.public_link
            except IntegrityError:
                if attempt == max_retries - 1:
                    file_logger.error(
                        "Failed to generate unique public link after %d attempts: file_id=%d",
                        max_retries,
                        self.id,  # pylint: disable=no-member
                    )
                    raise IntegrityError("Unable to generate unique public link") from None

                file_logger.warning(
                    "Public link collision detected (attempt %d/%d): file_id=%d, link=%s",
                    attempt + 1,
                    max_retries,
                    self.id,  # pylint: disable=no-member
                    self.public_link,
                )

        raise IntegrityError("Unable to generate unique public link")
