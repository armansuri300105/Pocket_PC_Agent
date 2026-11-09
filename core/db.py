"""Async SQLite database manager using aiosqlite."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Union

import aiosqlite

from core.config import get_settings


def _resolve_db_path(db_path: Optional[Union[str, Path]] = None) -> Path:
    """Resolve database path, defaulting to settings.DATABASE_PATH."""
    if db_path is None:
        target = get_settings().DATABASE_PATH
    else:
        target = Path(db_path)
    if str(target) != ":memory:":
        target.parent.mkdir(parents=True, exist_ok=True)
    return target


@asynccontextmanager
async def get_connection(
    db_path: Optional[Union[str, Path]] = None,
) -> AsyncGenerator[aiosqlite.Connection, None]:
    """Async context manager for SQLite database connection."""
    resolved_path = _resolve_db_path(db_path)
    conn = await aiosqlite.connect(str(resolved_path))
    conn.row_factory = aiosqlite.Row
    try:
        yield conn
    finally:
        await conn.close()


async def init_db(db_path: Optional[Union[str, Path]] = None) -> None:
    """Initialize database tables according to security and audit specifications."""
    async with get_connection(db_path) as conn:
        await conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                command TEXT NOT NULL,
                tier INTEGER NOT NULL,
                status TEXT NOT NULL,
                details TEXT
            );

            CREATE TABLE IF NOT EXISTS undo_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action_type TEXT NOT NULL,
                original_path TEXT NOT NULL,
                backup_path TEXT NOT NULL,
                restored_bool INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS shortcuts (
                trigger_phrase TEXT PRIMARY KEY,
                mapped_command TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS saved_skills (
                name TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                steps_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_undo_history_restored ON undo_history(restored_bool, id DESC);
            """
        )
        await conn.commit()


# ==========================================
# Audit Log Methods
# ==========================================


async def log_audit(
    command: str,
    tier: int,
    status: str,
    details: str = "",
    timestamp: Optional[str] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> int:
    """Log an event into audit_log table."""
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    async with get_connection(db_path) as conn:
        cursor = await conn.execute(
            """
            INSERT INTO audit_log (timestamp, command, tier, status, details)
            VALUES (?, ?, ?, ?, ?)
            """,
            (ts, command, tier, status, details),
        )
        await conn.commit()
        return cursor.lastrowid or 0


async def get_audit_logs(
    limit: int = 50,
    offset: int = 0,
    db_path: Optional[Union[str, Path]] = None,
) -> List[Dict[str, Any]]:
    """Retrieve audit log entries in reverse chronological order."""
    async with get_connection(db_path) as conn:
        async with conn.execute(
            """
            SELECT id, timestamp, command, tier, status, details
            FROM audit_log
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


# ==========================================
# Undo History Methods
# ==========================================


async def record_undo(
    action_type: str,
    original_path: str,
    backup_path: str,
    timestamp: Optional[str] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> int:
    """Record a file modification or deletion in undo_history."""
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    async with get_connection(db_path) as conn:
        cursor = await conn.execute(
            """
            INSERT INTO undo_history (timestamp, action_type, original_path, backup_path, restored_bool)
            VALUES (?, ?, ?, ?, 0)
            """,
            (ts, action_type, original_path, backup_path),
        )
        await conn.commit()
        return cursor.lastrowid or 0


async def get_latest_unrestored_undo(
    db_path: Optional[Union[str, Path]] = None,
) -> Optional[Dict[str, Any]]:
    """Get the most recent unrestored entry from undo_history."""
    async with get_connection(db_path) as conn:
        async with conn.execute(
            """
            SELECT id, timestamp, action_type, original_path, backup_path, restored_bool
            FROM undo_history
            WHERE restored_bool = 0
            ORDER BY id DESC
            LIMIT 1
            """
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


async def mark_undo_restored(
    undo_id: int,
    db_path: Optional[Union[str, Path]] = None,
) -> bool:
    """Mark an entry in undo_history as restored."""
    async with get_connection(db_path) as conn:
        cursor = await conn.execute(
            """
            UPDATE undo_history
            SET restored_bool = 1
            WHERE id = ?
            """,
            (undo_id,),
        )
        await conn.commit()
        return cursor.rowcount > 0


async def get_undo_history(
    limit: int = 50,
    db_path: Optional[Union[str, Path]] = None,
) -> List[Dict[str, Any]]:
    """Retrieve undo history entries."""
    async with get_connection(db_path) as conn:
        async with conn.execute(
            """
            SELECT id, timestamp, action_type, original_path, backup_path, restored_bool
            FROM undo_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


# ==========================================
# Shortcuts Methods
# ==========================================


async def add_shortcut(
    trigger_phrase: str,
    mapped_command: str,
    db_path: Optional[Union[str, Path]] = None,
) -> None:
    """Add or replace a user shortcut."""
    async with get_connection(db_path) as conn:
        await conn.execute(
            """
            INSERT OR REPLACE INTO shortcuts (trigger_phrase, mapped_command)
            VALUES (?, ?)
            """,
            (trigger_phrase.strip().lower(), mapped_command.strip()),
        )
        await conn.commit()


async def get_shortcut(
    trigger_phrase: str,
    db_path: Optional[Union[str, Path]] = None,
) -> Optional[str]:
    """Retrieve mapped command for a trigger phrase."""
    async with get_connection(db_path) as conn:
        async with conn.execute(
            """
            SELECT mapped_command
            FROM shortcuts
            WHERE trigger_phrase = ?
            """,
            (trigger_phrase.strip().lower(),),
        ) as cursor:
            row = await cursor.fetchone()
            return row["mapped_command"] if row else None


async def list_shortcuts(
    db_path: Optional[Union[str, Path]] = None,
) -> Dict[str, str]:
    """List all shortcuts as a dictionary mapping trigger_phrase to mapped_command."""
    async with get_connection(db_path) as conn:
        async with conn.execute(
            """
            SELECT trigger_phrase, mapped_command
            FROM shortcuts
            ORDER BY trigger_phrase ASC
            """
        ) as cursor:
            rows = await cursor.fetchall()
            return {row["trigger_phrase"]: row["mapped_command"] for row in rows}


async def remove_shortcut(
    trigger_phrase: str,
    db_path: Optional[Union[str, Path]] = None,
) -> bool:
    """Remove a shortcut by trigger phrase."""
    async with get_connection(db_path) as conn:
        cursor = await conn.execute(
            """
            DELETE FROM shortcuts
            WHERE trigger_phrase = ?
            """,
            (trigger_phrase.strip().lower(),),
        )
        await conn.commit()
        return cursor.rowcount > 0


# ==========================================
# Saved Skills Methods
# ==========================================


async def save_skill_record(
    name: str,
    description: str,
    steps_json: str,
    timestamp: Optional[str] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> None:
    """Save or update a named skill record."""
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    async with get_connection(db_path) as conn:
        await conn.execute(
            """
            INSERT OR REPLACE INTO saved_skills (name, description, steps_json, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (name.strip().lower(), description.strip(), steps_json, ts),
        )
        await conn.commit()


async def get_skill_record(
    name: str,
    db_path: Optional[Union[str, Path]] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieve a saved skill by name."""
    async with get_connection(db_path) as conn:
        async with conn.execute(
            """
            SELECT name, description, steps_json, created_at
            FROM saved_skills
            WHERE name = ?
            """,
            (name.strip().lower(),),
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


async def list_skill_records(
    db_path: Optional[Union[str, Path]] = None,
) -> List[Dict[str, Any]]:
    """List all saved skills."""
    async with get_connection(db_path) as conn:
        async with conn.execute(
            """
            SELECT name, description, steps_json, created_at
            FROM saved_skills
            ORDER BY name ASC
            """
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


async def delete_skill_record(
    name: str,
    db_path: Optional[Union[str, Path]] = None,
) -> bool:
    """Delete a saved skill by name."""
    async with get_connection(db_path) as conn:
        cursor = await conn.execute(
            """
            DELETE FROM saved_skills
            WHERE name = ?
            """,
            (name.strip().lower(),),
        )
        await conn.commit()
        return cursor.rowcount > 0

