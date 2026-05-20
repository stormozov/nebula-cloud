"""
Test suite for throttles module – fully isolated from Django settings.
"""

from unittest.mock import patch
from ..throttles import LoginRateThrottle, RegisterRateThrottle, PasswordResetRateThrottle


class MockRequest:
    """Simple request mock with user and data attributes."""

    def __init__(self, user=None, data=None):
        self.user = user or type("User", (), {"is_authenticated": False})()
        self.data = data or {}


class TestLoginRateThrottle:
    """Test suite for LoginRateThrottle custom cache key generation."""

    def test_authenticated_user_returns_none(self):
        """
        Test that cache key is None for an already authenticated user.

        Scenario:
            A request with an authenticated user is passed to get_cache_key.

        Expected Result:
            - Method returns None regardless of other parameters.
        """

        # Arrange
        with patch.dict(
            "rest_framework.throttling.AnonRateThrottle.THROTTLE_RATES",
            {"login": "5/hour"},
            clear=False,
        ):
            throttle = LoginRateThrottle()
        request = MockRequest(
            user=type("User", (), {"is_authenticated": True})(),
            data={"username": "testuser"},
        )

        # Act
        key = throttle.get_cache_key(request, None)

        # Assert
        assert key is None

    def test_missing_username_returns_none(self):
        """
        Test that cache key is None when no username is provided.

        Scenario:
            A request without a username in data is passed.

        Expected Result:
            - Method returns None even if the user is not authenticated.
        """

        # Arrange
        with patch.dict(
            "rest_framework.throttling.AnonRateThrottle.THROTTLE_RATES",
            {"login": "5/hour"},
            clear=False,
        ):
            throttle = LoginRateThrottle()
        request = MockRequest(data={})

        # Act
        key = throttle.get_cache_key(request, None)

        # Assert
        assert key is None

    def test_unauthenticated_user_with_username_returns_expected_key(self):
        """
        Test that a cache key is built correctly for unauthenticated user with username.

        Scenario:
            An unauthenticated request contains a username.
            The throttle's get_ident returns a fixed IP-like identifier.

        Expected Result:
            - Key is formed as cache_format % {scope, ident + '_' + username}.
        """

        # Arrange
        with patch.dict(
            "rest_framework.throttling.AnonRateThrottle.THROTTLE_RATES",
            {"login": "5/hour"},
            clear=False,
        ):
            throttle = LoginRateThrottle()
        throttle.scope = "login"
        throttle.cache_format = "throttle_%(scope)s_%(ident)s"
        request = MockRequest(data={"username": "targetuser"})

        with patch.object(throttle, "get_ident", return_value="client1"):
            # Act
            key = throttle.get_cache_key(request, None)

        # Assert
        assert key == "throttle_login_client1_targetuser"


class TestRegisterRateThrottle:
    """Test suite for RegisterRateThrottle – mostly default behaviour."""

    def test_scope_is_register(self):
        """
        Test that the scope attribute is correctly set to 'register'.

        Scenario:
            An instance of RegisterRateThrottle is created.

        Expected Result:
            - instance.scope equals 'register'.
        """

        # Arrange & Act
        with patch.dict(
            "rest_framework.throttling.AnonRateThrottle.THROTTLE_RATES",
            {"register": "5/hour"},
            clear=False,
        ):
            throttle = RegisterRateThrottle()

        # Assert
        assert throttle.scope == "register"

    def test_get_cache_key_uses_default_behaviour(self):
        """
        Test that get_cache_key works without custom account binding (standard client ident only).

        Scenario:
            Unauthenticated request, no custom data filtering.

        Expected Result:
            - Key is formed from scope and ident only (no username appended).
        """

        # Arrange
        with patch.dict(
            "rest_framework.throttling.AnonRateThrottle.THROTTLE_RATES",
            {"register": "5/hour"},
            clear=False,
        ):
            throttle = RegisterRateThrottle()
        throttle.scope = "register"
        throttle.cache_format = "throttle_%(scope)s_%(ident)s"
        request = MockRequest(data={"username": "ignored"})  # data irrelevant

        with patch.object(throttle, "get_ident", return_value="client2"):
            # Act
            key = throttle.get_cache_key(request, None)

        # Assert
        assert key == "throttle_register_client2"


class TestPasswordResetRateThrottle:
    """Test suite for PasswordResetRateThrottle email-based cache key."""

    def test_missing_email_returns_none(self):
        """
        Test that cache key is None when email is missing.

        Scenario:
            Request data does not contain an email field.

        Expected Result:
            - Method returns None.
        """

        # Arrange
        with patch.dict(
            "rest_framework.throttling.AnonRateThrottle.THROTTLE_RATES",
            {"password_reset": "5/hour"},
            clear=False,
        ):
            throttle = PasswordResetRateThrottle()
        request = MockRequest(data={})

        # Act
        key = throttle.get_cache_key(request, None)

        # Assert
        assert key is None

    def test_with_email_returns_expected_key(self):
        """
        Test that providing an email generates the correct cache key.

        Scenario:
            Request data contains an email.
            get_ident returns a fixed identifier.

        Expected Result:
            - Key is formed as scope + ident + '_' + email.
        """

        # Arrange
        with patch.dict(
            "rest_framework.throttling.AnonRateThrottle.THROTTLE_RATES",
            {"password_reset": "5/hour"},
            clear=False,
        ):
            throttle = PasswordResetRateThrottle()
        throttle.scope = "password_reset"
        throttle.cache_format = "throttle_%(scope)s_%(ident)s"
        request = MockRequest(data={"email": "user@example.com"})

        with patch.object(throttle, "get_ident", return_value="client3"):
            # Act
            key = throttle.get_cache_key(request, None)

        # Assert
        assert key == "throttle_password_reset_client3_user@example.com"
