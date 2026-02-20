"""
Utility functions for the users app.
"""


def format_size(size_bytes: int) -> str:
    """Format bytes to human-readable size."""

    if size_bytes <= 0:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB", "PB"]

    return next(
        f"{size_bytes / (1024**i):.2f} {unit}"
        for i, unit in enumerate(units)
        if (size_bytes < 1024 ** (i + 1)) or (i == len(units) - 1)
    )
