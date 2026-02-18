"""
IP address utilities for Django applications.

This module contains helper functions to safely extract the client's IP address
from HTTP requests in Django views, taking into account common proxy and load balancer
scenarios where the original IP is passed via headers (e.g., X‑Forwarded‑For).

Functions:
    get_client_ip(request) -> str:
        Extracts the client IP address from the request, considering proxy headers.
"""


def get_client_ip(request) -> str:
    """Extracts the client IP address from the request, considering proxy headers."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    return (
        x_forwarded_for.split(",")[0]
        if x_forwarded_for
        else request.META.get("REMOTE_ADDR", "unknown")
    )
