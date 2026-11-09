"""Windows Sleep Prevention (Caffeinate) module.

Uses Windows ctypes.windll.kernel32.SetThreadExecutionState to keep the host
machine awake while the PocketPC daemon is running, with safe no-op fallback
on Linux and macOS.
"""

from __future__ import annotations

import ctypes
import logging
import os

logger = logging.getLogger(__name__)

# Windows Thread Execution State Flags
ES_CONTINUOUS: int = 0x80000000
ES_SYSTEM_REQUIRED: int = 0x00000001
ES_DISPLAY_REQUIRED: int = 0x00000002
ES_AWAYMODE_REQUIRED: int = 0x00000040

_IS_AWAKE_ENABLED: bool = False


def enable_keep_awake(display: bool = False) -> bool:
    """Prevent the OS from going to sleep while the agent daemon runs."""
    global _IS_AWAKE_ENABLED
    if os.name == "nt":
        try:
            flags = ES_CONTINUOUS | ES_SYSTEM_REQUIRED
            if display:
                flags |= ES_DISPLAY_REQUIRED
            ctypes.windll.kernel32.SetThreadExecutionState(flags)
            _IS_AWAKE_ENABLED = True
            logger.info("Sleep prevention enabled (Windows SetThreadExecutionState).")
            return True
        except Exception as e:
            logger.error("Failed to enable sleep prevention: %s", e)
            return False
    else:
        # Safe no-op on Linux / macOS
        _IS_AWAKE_ENABLED = True
        logger.info("Sleep prevention requested on non-Windows platform (no-op).")
        return True


def disable_keep_awake() -> bool:
    """Restore default OS power and sleep behavior."""
    global _IS_AWAKE_ENABLED
    if os.name == "nt":
        try:
            ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS)
            _IS_AWAKE_ENABLED = False
            logger.info("Sleep prevention disabled (restored default sleep state).")
            return True
        except Exception as e:
            logger.error("Failed to disable sleep prevention: %s", e)
            return False
    else:
        _IS_AWAKE_ENABLED = False
        return True


def is_keep_awake_enabled() -> bool:
    """Return True if sleep prevention is currently active."""
    return _IS_AWAKE_ENABLED
