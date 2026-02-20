"""
Logging configuration for storage app.

This module provides custom loggers for:
- General storage operations
- File access and manipulation events
"""

import logging

# General storage logger
logger = logging.getLogger("storage")

# File access logger (for download/upload events)
file_logger = logging.getLogger("storage.file")
