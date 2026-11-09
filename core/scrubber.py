"""Pre-Flight Secret Scrubber.

Redacts API keys, Bearer tokens, .env key-value secrets, IPv4:port endpoints,
and credit card numbers into [REDACTED_SECRET] before any text is dispatched to an LLM.
"""

from __future__ import annotations

import re
from typing import List, Tuple

# Redaction placeholder token
REDACTED_TOKEN = "[REDACTED_SECRET]"

# Compiled regex patterns for credential detection and redaction
_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # 1. OpenAI API Keys (sk-proj-..., sk-admin-..., or classic sk-...)
    (
        re.compile(r"sk-(?:proj-|admin-|svcacct-)?[a-zA-Z0-9_\-]{20,}"),
        REDACTED_TOKEN,
    ),
    # 2. Anthropic API Keys (sk-ant-...)
    (
        re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}"),
        REDACTED_TOKEN,
    ),
    # 3. Groq API Keys (gsk_...)
    (
        re.compile(r"gsk_[a-zA-Z0-9_\-]{20,}"),
        REDACTED_TOKEN,
    ),
    # 4. GitHub Tokens (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_...)
    (
        re.compile(r"(?:(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})"),
        REDACTED_TOKEN,
    ),
    # 5. Authorization Bearer Tokens (e.g. Bearer eyJhbGci...)
    (
        re.compile(r"(?i)\bbearer\s+[a-zA-Z0-9_\-\.]{20,}"),
        f"Bearer {REDACTED_TOKEN}",
    ),
    # 6. .env Key=Value assignments containing sensitive keywords
    (
        re.compile(
            r"(?i)\b([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASS|AUTH|PWD|CREDENTIAL|PRIVATE)[A-Z0-9_]*\s*=\s*)([\"'][^\"']*[\"']|[^\s\r\n]+)"
        ),
        rf"\g<1>{REDACTED_TOKEN}",
    ),
    # 7. IPv4 addresses with specific ports (e.g. 192.168.1.100:8080)
    (
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?):\d{2,5}\b"),
        REDACTED_TOKEN,
    ),
    # 8. 16-digit credit card numbers (grouped by 4 digits or continuous)
    (
        re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        REDACTED_TOKEN,
    ),
]


def scrub_secrets(text: str) -> str:
    """Scrub and redact all sensitive credentials and secrets from text.

    Returns the scrubbed string with secrets replaced by [REDACTED_SECRET].
    """
    if not text:
        return text

    scrubbed = text
    for pattern, replacement in _PATTERNS:
        scrubbed = pattern.sub(replacement, scrubbed)

    return scrubbed


def contains_secrets(text: str) -> bool:
    """Check whether text contains any un-redacted secret patterns."""
    if not text:
        return False

    for pattern, _ in _PATTERNS:
        if pattern.search(text):
            return True
    return False
