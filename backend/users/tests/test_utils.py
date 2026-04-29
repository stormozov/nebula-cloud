"""
Test suite for utility functions in the users app.
"""

from users.utils import get_client_ip


class MockRequest:
    """Minimal request mock exposing a META dict."""

    def __init__(self, meta: dict):
        self.META = meta


class TestGetClientIP:
    """Test suite for get_client_ip utility that extracts client IP from request metadata."""

    def test_x_forwarded_for_multiple_ips_returns_first(self):
        """
        Test that the first IP is returned when X-Forwarded-For contains multiple addresses.

        Scenario:
            Request has HTTP_X_FORWARDED_FOR header with a comma-separated list of IPs.

        Expected Result:
            - The first IP (before any comma) is returned as a string.
        """

        # Arrange
        request = MockRequest({"HTTP_X_FORWARDED_FOR": "192.168.1.10, 10.0.0.1, 172.16.0.5"})

        # Act
        ip = get_client_ip(request)

        # Assert
        assert ip == "192.168.1.10"

    def test_x_forwarded_for_single_ip_returns_that_ip(self):
        """
        Test that a single IP in X-Forwarded-For is returned unchanged.

        Scenario:
            Request has HTTP_X_FORWARDED_FOR with exactly one IP address.

        Expected Result:
            - The IP is returned as-is.
        """

        # Arrange
        request = MockRequest({"HTTP_X_FORWARDED_FOR": "10.0.0.1"})

        # Act
        ip = get_client_ip(request)

        # Assert
        assert ip == "10.0.0.1"

    def test_no_x_forwarded_for_remote_addr_present(self):
        """
        Test fallback to REMOTE_ADDR when X-Forwarded-For header is missing.

        Scenario:
            HTTP_X_FORWARDED_FOR is not present; REMOTE_ADDR is set to a valid IP.

        Expected Result:
            - The value of REMOTE_ADDR is returned.
        """

        # Arrange
        request = MockRequest({"REMOTE_ADDR": "127.0.0.1"})

        # Act
        ip = get_client_ip(request)

        # Assert
        assert ip == "127.0.0.1"

    def test_no_x_forwarded_for_remote_addr_missing(self):
        """
        Test fallback default when both X-Forwarded-For and REMOTE_ADDR are absent.

        Scenario:
            Neither HTTP_X_FORWARDED_FOR nor REMOTE_ADDR are present in the META.

        Expected Result:
            - The string "unknown" is returned.
        """

        # Arrange
        request = MockRequest({})  # empty META

        # Act
        ip = get_client_ip(request)

        # Assert
        assert ip == "unknown"

    def test_x_forwarded_for_empty_string_remote_addr_present(self):
        """
        Test that an empty X-Forwarded-For header is treated as falsy and falls back to REMOTE_ADDR.

        Scenario:
            HTTP_X_FORWARDED_FOR is an empty string; REMOTE_ADDR is available.

        Expected Result:
            - The function ignores the empty X-Forwarded-For and returns REMOTE_ADDR.
        """

        # Arrange
        request = MockRequest({"HTTP_X_FORWARDED_FOR": "", "REMOTE_ADDR": "10.0.0.2"})

        # Act
        ip = get_client_ip(request)

        # Assert
        assert ip == "10.0.0.2"

    def test_x_forwarded_for_empty_string_remote_addr_missing(self):
        """
        Test that an empty X-Forwarded-For header with missing REMOTE_ADDR returns the default.

        Scenario:
            HTTP_X_FORWARDED_FOR is an empty string and REMOTE_ADDR is not set.

        Expected Result:
            - The function returns "unknown".
        """

        # Arrange
        request = MockRequest({"HTTP_X_FORWARDED_FOR": ""})

        # Act
        ip = get_client_ip(request)

        # Assert
        assert ip == "unknown"
