"""
Logging configuration for users app.
"""

import logging

# Main logger for users app
logger = logging.getLogger("users")

# Logger for user authentication
auth_logger = logging.getLogger("users.auth")
