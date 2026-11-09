"""Deterministic 4-Tier Permission Gate and security rule enforcement.

Strict Rule: AI NEVER decides permissions. All permission tiers and regex guards
are deterministically computed and enforced in this module before any tool executes.
"""

from __future__ import annotations

from enum import IntEnum
import re
from typing import Any, Dict, List, Optional, Union


class SecurityTier(IntEnum):
    """Deterministic 4-Tier Permission Gate levels."""
    TIER_1_AUTO = 1      # Auto-execute (read-only, zero risk)
    TIER_2_CONFIRM = 2   # Requires explicit YES button confirmation
    TIER_3_PIN = 3       # Requires YES confirmation + 4-digit safety PIN
    TIER_4_BLOCKED = 4   # Catastrophic / hard-blocked (cannot execute under any circumstances)


# Deterministic registry mapping every tool name to its mandatory base SecurityTier
TOOL_TIER_REGISTRY: Dict[str, SecurityTier] = {
    # Tier 1: Auto-Execute (Read-only / Safe system diagnostics)
    "explore_path": SecurityTier.TIER_1_AUTO,
    "deliver_path": SecurityTier.TIER_1_AUTO,
    "get_system_vitals": SecurityTier.TIER_1_AUTO,
    "system_vitals": SecurityTier.TIER_1_AUTO,
    "vitals": SecurityTier.TIER_1_AUTO,
    "capture_screenshot": SecurityTier.TIER_1_AUTO,
    "take_screenshot": SecurityTier.TIER_1_AUTO,
    "screenshot": SecurityTier.TIER_1_AUTO,
    "find_files": SecurityTier.TIER_1_AUTO,
    "find_file": SecurityTier.TIER_1_AUTO,
    "search_files": SecurityTier.TIER_1_AUTO,
    "undo_last_action": SecurityTier.TIER_1_AUTO,
    "undo": SecurityTier.TIER_1_AUTO,
    "list_shortcuts": SecurityTier.TIER_1_AUTO,
    "get_shortcut": SecurityTier.TIER_1_AUTO,
    "get_status": SecurityTier.TIER_1_AUTO,
    "list_running_services": SecurityTier.TIER_1_AUTO,
    "get_service_logs": SecurityTier.TIER_1_AUTO,
    "caffeinate_status": SecurityTier.TIER_1_AUTO,
    "send_file": SecurityTier.TIER_1_AUTO,
    "send_folder_files": SecurityTier.TIER_1_AUTO,
    "package_folder_files": SecurityTier.TIER_1_AUTO,
    "get_file": SecurityTier.TIER_1_AUTO,
    "download_file": SecurityTier.TIER_1_AUTO,
    "inspect_project": SecurityTier.TIER_1_AUTO,
    "list_directory": SecurityTier.TIER_1_AUTO,
    "list_dir": SecurityTier.TIER_1_AUTO,
    "list_folders": SecurityTier.TIER_1_AUTO,
    "ls": SecurityTier.TIER_1_AUTO,
    "dir": SecurityTier.TIER_1_AUTO,

    # Tier 2: Confirmation Required (State-modifying / low risk)
    "move_file": SecurityTier.TIER_2_CONFIRM,
    "safe_move": SecurityTier.TIER_2_CONFIRM,
    "zip_folder": SecurityTier.TIER_2_CONFIRM,
    "zip_and_prepare": SecurityTier.TIER_2_CONFIRM,
    "start_service": SecurityTier.TIER_2_CONFIRM,
    "stop_service": SecurityTier.TIER_2_CONFIRM,
    "restart_service": SecurityTier.TIER_2_CONFIRM,
    "start_named_service": SecurityTier.TIER_2_CONFIRM,
    "stop_named_service": SecurityTier.TIER_2_CONFIRM,
    "expose_port_tunnel": SecurityTier.TIER_2_CONFIRM,
    "caffeinate_toggle": SecurityTier.TIER_2_CONFIRM,
    "add_shortcut": SecurityTier.TIER_2_CONFIRM,
    "remove_shortcut": SecurityTier.TIER_2_CONFIRM,

    # Tier 3: PIN Required (Destructive / High privilege)
    "delete_file": SecurityTier.TIER_3_PIN,
    "safe_delete": SecurityTier.TIER_3_PIN,
    "kill_process": SecurityTier.TIER_3_PIN,
    "run_shell": SecurityTier.TIER_3_PIN,
    "execute_command": SecurityTier.TIER_3_PIN,
    "reboot_system": SecurityTier.TIER_3_PIN,
    "shutdown_system": SecurityTier.TIER_3_PIN,

    # Tier 4: Hard-Blocked (Catastrophic / Unauthorized)
    "format_disk": SecurityTier.TIER_4_BLOCKED,
    "edit_registry": SecurityTier.TIER_4_BLOCKED,
    "disable_firewall": SecurityTier.TIER_4_BLOCKED,
}


# Regex patterns for Tier 4 forbidden keywords and destructive commands
TIER_4_FORBIDDEN_PATTERNS: List[str] = [
    r"\bformat(\s+.*|\.[a-zA-Z]+)?\b",                          # format command / disk formatting
    r"\bregedit(\.exe)?\b",                                     # Registry Editor GUI
    r"\breg(\.exe)?\s+(add|delete|copy|save|restore|load|unload)\b", # Reg CLI modification
    r"netsh\s+advfirewall",                                     # Firewall alteration
    r"rm\s+-[rRfF]{1,3}\s+(/|\*|~|/\*)",                        # rm -rf / or root deletions
    r"del\s+.*(/[fF]|/[sS]|/[qQ])",                             # del /f /s /q forced silent deletions
    r"(rmdir|rd)\s+.*(/[sS]|/[qQ])",                            # Windows silent directory tree deletions
    r"\bbcdedit\b",                                             # Boot configuration manipulation
    r"vssadmin\s+delete\s+shadows",                             # Volume shadow copy deletion
    r"\bdiskpart\b",                                            # Disk partitioning CLI
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",               # Bash fork bomb
]

COMPILED_TIER_4_PATTERNS = [
    re.compile(pattern, re.IGNORECASE) for pattern in TIER_4_FORBIDDEN_PATTERNS
]


def check_forbidden_patterns(text: str) -> Optional[str]:
    """Scan text for any Tier 4 forbidden keywords or patterns.

    Returns the matched pattern substring if a match is found, or None.
    """
    if not text:
        return None

    for pattern in COMPILED_TIER_4_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)

    return None


def is_command_blocked(command: str) -> bool:
    """Return True if command triggers a Tier 4 hard-blocked pattern."""
    return check_forbidden_patterns(command) is not None


def get_tool_tier(
    tool_name: str,
    args: Optional[Union[Dict[str, Any], str]] = None,
) -> SecurityTier:
    """Deterministically determine the mandatory SecurityTier for a tool and its arguments.

    1. Checks the tool against TOOL_TIER_REGISTRY.
    2. Scans all arguments for Tier 4 forbidden patterns. If found, forces TIER_4_BLOCKED.
    3. Defaults unknown tools to TIER_3_PIN for safety.
    """
    normalized_name = tool_name.strip().lower()

    # Look up tool in registry; default to Tier 3 if unknown for strict security
    base_tier = TOOL_TIER_REGISTRY.get(normalized_name, SecurityTier.TIER_3_PIN)

    # If already Tier 4, keep it blocked
    if base_tier == SecurityTier.TIER_4_BLOCKED:
        return SecurityTier.TIER_4_BLOCKED

    # Scan arguments for forbidden patterns
    if args:
        texts_to_scan: List[str] = []
        if isinstance(args, str):
            texts_to_scan.append(args)
        elif isinstance(args, dict):
            for val in args.values():
                if isinstance(val, str):
                    texts_to_scan.append(val)
                elif isinstance(val, (list, tuple)):
                    texts_to_scan.extend(str(item) for item in val)

        for text in texts_to_scan:
            if check_forbidden_patterns(text):
                return SecurityTier.TIER_4_BLOCKED

    return base_tier
