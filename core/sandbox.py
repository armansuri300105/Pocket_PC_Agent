"""Sandbox directory jail and undo engine implementation.

Enforces:
1. Strict directory jail preventing path traversal outside ALLOWED_DIRS.
2. Safe delete and move operations that back up to UNDO_DIR without calling os.remove/Path.unlink.
3. Multi-step undo restoration from SQLite undo_history.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
from typing import Any, Dict, List, Optional, Union
import uuid

from core.config import get_settings
from core import db
from core.smart_resolver import SmartFileResolver


def clean_conversational_path(path_val: Union[str, Path]) -> str:
    """Strip conversational wrappers like 'the file named', 'the folder at', and surrounding quotes."""
    s = str(path_val).strip().strip("'\"")
    cleaned = re.sub(
        r"^(?:the\s+)?(?:file|folder|directory)\s+(?:named|called|at|in|present\s+in|to)?\s*",
        "",
        s,
        flags=re.IGNORECASE,
    ).strip().strip("'\"")
    return cleaned if cleaned else s


def is_path_allowed(
    target_path: Union[str, Path],
    allowed_dirs: Optional[List[Union[str, Path]]] = None,
) -> bool:
    """Check if target_path is strictly within one of the allowed directories.

    Resolves symlinks and relative segments (e.g., `../`) to prevent directory traversal.
    """
    if not target_path:
        return False

    try:
        target = Path(target_path).resolve()
    except Exception:
        return False

    if allowed_dirs is None:
        configured_dirs = get_settings().ALLOWED_DIRS
    else:
        configured_dirs = [Path(d).resolve() for d in allowed_dirs]

    for allowed in configured_dirs:
        try:
            allowed_resolved = Path(allowed).resolve()
            if target.is_relative_to(allowed_resolved):
                return True
        except (ValueError, AttributeError):
            continue

    return False


async def safe_delete(
    target_path: Union[str, Path],
    allowed_dirs: Optional[List[Union[str, Path]]] = None,
    undo_dir: Optional[Union[str, Path]] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Safely delete a file or directory by moving it to UNDO_DIR.

    Never deletes directly with os.remove or Path.unlink.
    Resolves fuzzy and conversational target paths via SmartFileResolver.
    Records the operation in undo_history and audit_log.
    """
    clean_target = clean_conversational_path(target_path)
    direct_cand = Path(clean_target)

    # 1. Enforce strict directory traversal check if path contains .. or is an out-of-bounds absolute path
    if direct_cand.is_absolute() or ".." in direct_cand.parts or ".." in str(target_path):
        if not is_path_allowed(direct_cand.resolve(), allowed_dirs=allowed_dirs):
            raise PermissionError(
                f"Path traversal detected or access denied: '{target_path}' is outside allowed directories."
            )

    # 2. Resolve target using SmartFileResolver
    try:
        resolver = SmartFileResolver.get_instance()
        target = resolver.resolve(clean_target, allowed_dirs=allowed_dirs)
    except FileNotFoundError:
        # Fallback to direct resolution if it exists on disk
        if direct_cand.exists() and is_path_allowed(direct_cand.resolve(), allowed_dirs=allowed_dirs):
            target = direct_cand.resolve()
        else:
            return {
                "status": "error",
                "message": f"Could not locate file matching '{target_path}'",
            }

    # 3. Double-check directory jail on resolved target
    if not is_path_allowed(target, allowed_dirs=allowed_dirs):
        raise PermissionError(
            f"Path traversal detected or access denied: '{target_path}' is outside allowed directories."
        )

    # 4. Prevent deleting root of allowed directories
    active_allowed = [
        Path(d).resolve()
        for d in (allowed_dirs if allowed_dirs is not None else get_settings().ALLOWED_DIRS)
    ]
    if target in active_allowed:
        raise PermissionError(
            f"Access denied: Cannot delete root allowed directory '{target}'."
        )

    # 5. Check file/directory existence
    if not target.exists():
        return {
            "status": "error",
            "message": f"Could not locate file matching '{target_path}'",
        }

    # 6. Prepare backup destination in UNDO_DIR
    storage_root = Path(undo_dir).resolve() if undo_dir else get_settings().UNDO_DIR
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    unique_id = uuid.uuid4().hex[:8]
    backup_subdir = storage_root / f"{timestamp}_{unique_id}"
    backup_subdir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_subdir / target.name

    # 7. Non-blocking move into undo storage
    is_dir = target.is_dir()
    await asyncio.to_thread(shutil.move, str(target), str(backup_path))

    # 8. Save metadata for safe audit and restore
    meta_path = backup_subdir / "meta.json"
    meta_data = {
        "action_type": "delete",
        "original_path": str(target),
        "backup_path": str(backup_path),
        "is_dir": is_dir,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    meta_path.write_text(json.dumps(meta_data, indent=2), encoding="utf-8")

    # 9. Record in undo_history and audit_log
    undo_id = await db.record_undo(
        action_type="delete",
        original_path=str(target),
        backup_path=str(backup_path),
        db_path=db_path,
    )
    await db.log_audit(
        command=f"safe_delete {target.name}",
        tier=2,
        status="SUCCESS",
        details=f"Moved '{target}' to '{backup_path}' (undo_id={undo_id})",
        db_path=db_path,
    )

    return {
        "status": "success",
        "undo_id": undo_id,
        "action_type": "delete",
        "original_path": str(target),
        "backup_path": str(backup_path),
    }


async def safe_move(
    src: Union[str, Path],
    dst: Union[str, Path],
    allowed_dirs: Optional[List[Union[str, Path]]] = None,
    undo_dir: Optional[Union[str, Path]] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Safely move a file or directory within allowed directories.

    Resolves source and destination directories via SmartFileResolver.
    Creates a backup in UNDO_DIR first and logs to undo_history.
    """
    clean_src = clean_conversational_path(src)
    clean_dst = clean_conversational_path(dst)

    candidate_src = Path(clean_src)
    candidate_dst = Path(clean_dst)

    # 1. Enforce directory traversal checks upfront
    if candidate_src.is_absolute() or ".." in candidate_src.parts or ".." in str(src):
        if not is_path_allowed(candidate_src.resolve(), allowed_dirs=allowed_dirs):
            raise PermissionError(
                f"Path traversal detected or access denied: Source '{src}' is outside allowed directories."
            )
    if candidate_dst.is_absolute() or ".." in candidate_dst.parts or ".." in str(dst):
        if not is_path_allowed(candidate_dst.resolve(), allowed_dirs=allowed_dirs):
            raise PermissionError(
                f"Path traversal detected or access denied: Destination '{dst}' is outside allowed directories."
            )

    # 2. Resolve source using SmartFileResolver
    try:
        resolver = SmartFileResolver.get_instance()
        resolved_src = resolver.resolve(clean_src, allowed_dirs=allowed_dirs)
    except FileNotFoundError:
        if candidate_src.exists() and is_path_allowed(candidate_src.resolve(), allowed_dirs=allowed_dirs):
            resolved_src = candidate_src.resolve()
        else:
            return {
                "status": "error",
                "message": f"Could not locate source file matching '{src}'",
            }

    # 3. Resolve destination
    if candidate_dst.is_absolute():
        resolved_dst = candidate_dst.resolve()
    else:
        parent_part = candidate_dst.parent
        if parent_part != Path("."):
            try:
                resolver = SmartFileResolver.get_instance()
                resolved_parent = resolver.resolve(str(parent_part), allowed_dirs=allowed_dirs)
                resolved_dst = (resolved_parent / candidate_dst.name).resolve()
            except Exception:
                base = (
                    Path(allowed_dirs[0]).resolve()
                    if allowed_dirs
                    else get_settings().ALLOWED_DIRS[0]
                )
                resolved_dst = (base / candidate_dst).resolve()
        else:
            # Single filename or directory name
            try:
                resolver = SmartFileResolver.get_instance()
                cand_folder = resolver.resolve(clean_dst, allowed_dirs=allowed_dirs)
                if cand_folder.is_dir():
                    resolved_dst = (cand_folder / resolved_src.name).resolve()
                else:
                    resolved_dst = (resolved_src.parent / candidate_dst.name).resolve()
            except Exception:
                resolved_dst = (resolved_src.parent / candidate_dst.name).resolve()

    # 4. Enforce directory jail on resolved paths
    if not is_path_allowed(resolved_src, allowed_dirs=allowed_dirs):
        raise PermissionError(
            f"Path traversal detected or access denied: Source '{src}' is outside allowed directories."
        )
    if not is_path_allowed(resolved_dst, allowed_dirs=allowed_dirs):
        raise PermissionError(
            f"Path traversal detected or access denied: Destination '{dst}' is outside allowed directories."
        )

    # 5. Prevent moving root allowed directories
    active_allowed = [
        Path(d).resolve()
        for d in (allowed_dirs if allowed_dirs is not None else get_settings().ALLOWED_DIRS)
    ]
    if resolved_src in active_allowed:
        raise PermissionError(
            f"Access denied: Cannot move root allowed directory '{resolved_src}'."
        )

    # 6. Check source existence
    if not resolved_src.exists():
        return {
            "status": "error",
            "message": f"Could not locate source file matching '{src}'",
        }

    storage_root = Path(undo_dir).resolve() if undo_dir else get_settings().UNDO_DIR
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    unique_id = uuid.uuid4().hex[:8]

    # If destination is an existing directory, move inside it
    if resolved_dst.is_dir():
        actual_dst = resolved_dst / resolved_src.name
    else:
        actual_dst = resolved_dst

    # 7. If destination already exists, safely backup existing dst first
    if actual_dst.exists():
        overwrite_subdir = storage_root / f"{timestamp}_{unique_id}_overwrite"
        overwrite_subdir.mkdir(parents=True, exist_ok=True)
        dst_backup = overwrite_subdir / actual_dst.name
        await asyncio.to_thread(shutil.move, str(actual_dst), str(dst_backup))
        await db.record_undo(
            action_type="overwrite",
            original_path=str(actual_dst),
            backup_path=str(dst_backup),
            db_path=db_path,
        )

    # 8. Create backup copy of source in undo storage
    backup_subdir = storage_root / f"{timestamp}_{unique_id}_move"
    backup_subdir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_subdir / resolved_src.name

    is_dir = resolved_src.is_dir()
    if is_dir:
        await asyncio.to_thread(shutil.copytree, str(resolved_src), str(backup_path))
    else:
        await asyncio.to_thread(shutil.copy2, str(resolved_src), str(backup_path))

    # Save metadata
    meta_path = backup_subdir / "meta.json"
    meta_data = {
        "action_type": "move",
        "original_path": str(resolved_src),
        "destination_path": str(actual_dst),
        "backup_path": str(backup_path),
        "is_dir": is_dir,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    meta_path.write_text(json.dumps(meta_data, indent=2), encoding="utf-8")

    # 9. Execute move to destination
    actual_dst.parent.mkdir(parents=True, exist_ok=True)
    await asyncio.to_thread(shutil.move, str(resolved_src), str(actual_dst))

    # 10. Record undo and audit
    undo_id = await db.record_undo(
        action_type="move",
        original_path=str(resolved_src),
        backup_path=str(backup_path),
        db_path=db_path,
    )
    await db.log_audit(
        command=f"safe_move {resolved_src.name} -> {actual_dst.name}",
        tier=2,
        status="SUCCESS",
        details=f"Moved '{resolved_src}' to '{actual_dst}' (undo_id={undo_id})",
        db_path=db_path,
    )

    return {
        "status": "success",
        "undo_id": undo_id,
        "action_type": "move",
        "original_path": str(resolved_src),
        "destination_path": str(actual_dst),
        "backup_path": str(backup_path),
    }


async def undo_last_action(
    undo_dir: Optional[Union[str, Path]] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> Optional[Dict[str, Any]]:
    """Restore the most recent un-restored action from undo_history.

    Returns details of restored action, or None if no action to restore.
    """
    entry = await db.get_latest_unrestored_undo(db_path=db_path)
    if entry is None:
        return None

    undo_id = entry["id"]
    action_type = entry["action_type"]
    original_path = Path(entry["original_path"])
    backup_path = Path(entry["backup_path"])

    if not backup_path.exists():
        raise FileNotFoundError(
            f"Undo failed: backup file or directory does not exist at '{backup_path}'."
        )

    storage_root = Path(undo_dir).resolve() if undo_dir else get_settings().UNDO_DIR
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    unique_id = uuid.uuid4().hex[:8]

    # Handle 'move' destination cleanup if applicable
    meta_path = backup_path.parent / "meta.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            dst_str = meta.get("destination_path")
            if dst_str:
                dst_path = Path(dst_str)
                if dst_path.exists() and dst_path.resolve() != original_path.resolve():
                    cleanup_subdir = storage_root / f"{timestamp}_{unique_id}_undo_cleanup"
                    cleanup_subdir.mkdir(parents=True, exist_ok=True)
                    cleanup_path = cleanup_subdir / dst_path.name
                    await asyncio.to_thread(shutil.move, str(dst_path), str(cleanup_path))
        except Exception:
            pass

    # If original_path currently exists, displace it safely into undo storage before restoring
    if original_path.exists():
        displace_subdir = storage_root / f"{timestamp}_{unique_id}_displaced"
        displace_subdir.mkdir(parents=True, exist_ok=True)
        displace_path = displace_subdir / original_path.name
        await asyncio.to_thread(shutil.move, str(original_path), str(displace_path))

    # Restore from backup_path to original_path
    original_path.parent.mkdir(parents=True, exist_ok=True)
    if backup_path.is_dir():
        await asyncio.to_thread(
            shutil.copytree, str(backup_path), str(original_path), dirs_exist_ok=True
        )
    else:
        await asyncio.to_thread(shutil.copy2, str(backup_path), str(original_path))

    # Mark as restored in database
    await db.mark_undo_restored(undo_id, db_path=db_path)

    # Log audit event
    await db.log_audit(
        command="undo_last_action",
        tier=1,
        status="SUCCESS",
        details=f"Restored {action_type} for '{original_path}' from '{backup_path}' (undo_id={undo_id})",
        db_path=db_path,
    )

    return {
        "undo_id": undo_id,
        "action_type": action_type,
        "original_path": str(original_path),
        "backup_path": str(backup_path),
        "restored": True,
    }
