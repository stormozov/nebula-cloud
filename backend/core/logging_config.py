"""
Logging configuration for the project.
"""

from pathlib import Path


def get_logging_config(base_dir: Path, debug: bool = False) -> dict:
    """
    Returns Django logging configuration dictionary.

    Args:
        base_dir: Base directory of the project
        debug: Debug mode flag

    Returns:
        Dictionary with logging configuration
    """

    logs_dir = base_dir / "logs"
    logs_dir.mkdir(exist_ok=True)

    max_bytes = 10 * 1024 * 1024  # 10 MB

    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "verbose": {
                "format": "[{levelname}] {asctime} — {name} — {message}",
                "style": "{",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
            "simple": {
                "format": "{levelname} {message}",
                "style": "{",
            },
        },
        "filters": {
            "require_debug_false": {
                "()": "django.utils.log.RequireDebugFalse",
            },
        },
        "handlers": {
            "console": {
                "level": "INFO",
                "class": "logging.StreamHandler",
                "formatter": "verbose",
            },
            "file": {
                "level": "INFO",
                "class": "logging.handlers.RotatingFileHandler",
                "filename": logs_dir / "app.log",
                "maxBytes": max_bytes,
                "backupCount": 5,
                "formatter": "verbose",
                "encoding": "utf-8",
            },
            "errors": {
                "level": "ERROR",
                "class": "logging.handlers.RotatingFileHandler",
                "filename": logs_dir / "errors.log",
                "maxBytes": max_bytes,
                "backupCount": 5,
                "formatter": "verbose",
                "encoding": "utf-8",
            },
            "security": {
                "level": "WARNING",
                "class": "logging.handlers.RotatingFileHandler",
                "filename": logs_dir / "security.log",
                "maxBytes": max_bytes,
                "backupCount": 5,
                "formatter": "verbose",
                "encoding": "utf-8",
            },
            "auth": {
                "level": "INFO",
                "class": "logging.handlers.RotatingFileHandler",
                "filename": logs_dir / "auth.log",
                "maxBytes": max_bytes,
                "backupCount": 5,
                "formatter": "verbose",
                "encoding": "utf-8",
            },
        },
        "loggers": {
            # Loggers from Django
            "django": {
                "handlers": ["console", "file", "errors"],
                "level": "INFO",
                "propagate": True,
            },
            "django.request": {
                "handlers": ["console", "errors"],
                "level": "ERROR",
                "propagate": False,
            },
            "django.security": {
                "handlers": ["security", "console"],
                "level": "WARNING",
                "propagate": False,
            },
            "django.db.backends": {
                "handlers": ["console"],
                "level": "INFO" if debug else "WARNING",
                "propagate": False,
            },
            # Loggers from other apps
            "users": {
                "handlers": ["console", "file", "errors"],
                "level": "INFO",
                "propagate": False,
            },
            "users.auth": {
                "handlers": ["auth", "security", "console"],
                "level": "INFO",
                "propagate": False,
            },
        },
    }
