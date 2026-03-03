"""
Common utility functions for Django applications.
"""

PUBLIC_URL_LEN = 21

# ==================================================================================================
# NETWORK UTILITIES
# ==================================================================================================


def get_client_ip(request) -> str:
    """Extracts the client IP address from the request, considering proxy headers."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    return (
        x_forwarded_for.split(",")[0]
        if x_forwarded_for
        else request.META.get("REMOTE_ADDR", "unknown")
    )


# ==================================================================================================
# FILE UTILITIES
# ==================================================================================================


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
