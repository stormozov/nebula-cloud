"""
Common utility functions for Django applications.
"""

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
