"""Tests for Phase 1: Foundation, Config, SQLite DB, and Sandbox Undo Engine."""

import os
from pathlib import Path
import pytest
import aiosqlite

from core.config import Settings, get_settings, reload_settings
from core import db
from core.sandbox import is_path_allowed, safe_delete, safe_move, undo_last_action


@pytest.fixture
async def setup_env(tmp_path):
    """Set up isolated sandbox files, undo storage, and SQLite database."""
    sandbox_dir = tmp_path / "sandbox_files"
    sandbox_dir.mkdir(parents=True, exist_ok=True)

    undo_dir = tmp_path / ".undo_storage"
    undo_dir.mkdir(parents=True, exist_ok=True)

    db_path = tmp_path / "test_pocket_pc.db"
    await db.init_db(db_path)

    yield {
        "sandbox_dir": sandbox_dir,
        "undo_dir": undo_dir,
        "db_path": db_path,
    }


# =====================================================================
# 1. Config & Settings Tests
# =====================================================================


def test_settings_defaults():
    """Verify default configurations conform to Phase 1 specifications."""
    settings = Settings()
    assert settings.SAFETY_PIN == "1234"
    assert settings.LLM_PROVIDER in ("ollama", "openai")
    assert settings.LLM_MODEL != ""
    assert isinstance(settings.ALLOWED_DIRS, list)
    assert len(settings.ALLOWED_DIRS) >= 1
    assert settings.UNDO_DIR.name == ".undo_storage"


def test_settings_allowed_dirs_parsing():
    """Test parsing of ALLOWED_DIRS from strings and lists."""
    # JSON list string
    s1 = Settings(ALLOWED_DIRS='["./custom_sandbox", "./extra_files"]')
    assert len(s1.ALLOWED_DIRS) == 2
    assert s1.ALLOWED_DIRS[0] == Path("./custom_sandbox").resolve()

    # Comma-separated string
    s2 = Settings(ALLOWED_DIRS="./dir1, ./dir2")
    assert len(s2.ALLOWED_DIRS) == 2
    assert s2.ALLOWED_DIRS[0] == Path("./dir1").resolve()


# =====================================================================
# 2. Directory Jail & Path Traversal Tests
# =====================================================================


def test_is_path_allowed_inside_and_outside():
    """Test is_path_allowed correctly identifies jail boundaries."""
    sandbox = Path("./sandbox_files").resolve()
    allowed_dirs = [sandbox]

    # Valid file inside sandbox
    assert is_path_allowed(sandbox / "doc.txt", allowed_dirs=allowed_dirs) is True
    assert is_path_allowed(sandbox / "nested" / "sub" / "file.pdf", allowed_dirs=allowed_dirs) is True

    # Path traversal with ../ outside sandbox
    traversal_path = sandbox / ".." / "secret.txt"
    assert is_path_allowed(traversal_path, allowed_dirs=allowed_dirs) is False

    # Deep traversal
    deep_traversal = sandbox / "nested" / ".." / ".." / "etc" / "passwd"
    assert is_path_allowed(deep_traversal, allowed_dirs=allowed_dirs) is False

    # Absolute path outside sandbox
    system_path = Path("C:/Windows/System32") if os.name == "nt" else Path("/etc/passwd")
    assert is_path_allowed(system_path, allowed_dirs=allowed_dirs) is False


@pytest.mark.asyncio
async def test_path_traversal_raises_permission_error(setup_env):
    """Verify that path traversal outside ./sandbox_files raises PermissionError."""
    sandbox_dir = setup_env["sandbox_dir"]
    undo_dir = setup_env["undo_dir"]
    db_path = setup_env["db_path"]
    allowed_dirs = [sandbox_dir]

    # 1. Traversal using ../
    traversal_target = sandbox_dir / ".." / "unauthorized.txt"
    with pytest.raises(PermissionError) as exc_info:
        await safe_delete(
            traversal_target,
            allowed_dirs=allowed_dirs,
            undo_dir=undo_dir,
            db_path=db_path,
        )
    assert "outside allowed directories" in str(exc_info.value).lower()

    # 2. Direct absolute path outside allowed dirs
    forbidden_target = Path("C:/secret_passwords.txt") if os.name == "nt" else Path("/root/secret.txt")
    with pytest.raises(PermissionError) as exc_info:
        await safe_delete(
            forbidden_target,
            allowed_dirs=allowed_dirs,
            undo_dir=undo_dir,
            db_path=db_path,
        )
    assert "outside allowed directories" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_safe_move_path_traversal_raises_permission_error(setup_env):
    """Verify that safe_move blocks traversal for both source and destination."""
    sandbox_dir = setup_env["sandbox_dir"]
    undo_dir = setup_env["undo_dir"]
    db_path = setup_env["db_path"]
    allowed_dirs = [sandbox_dir]

    valid_file = sandbox_dir / "sample.txt"
    valid_file.write_text("valid content", encoding="utf-8")

    # Move target outside allowed directory
    outside_dst = sandbox_dir / ".." / "escaped.txt"
    with pytest.raises(PermissionError) as exc_info:
        await safe_move(
            valid_file,
            outside_dst,
            allowed_dirs=allowed_dirs,
            undo_dir=undo_dir,
            db_path=db_path,
        )
    assert "outside allowed directories" in str(exc_info.value).lower()

    # Source outside allowed directory
    outside_src = sandbox_dir / ".." / "stolen.txt"
    with pytest.raises(PermissionError) as exc_info:
        await safe_move(
            outside_src,
            valid_file,
            allowed_dirs=allowed_dirs,
            undo_dir=undo_dir,
            db_path=db_path,
        )
    assert "outside allowed directories" in str(exc_info.value).lower()


# =====================================================================
# 3. Safe Delete & Undo Engine Tests
# =====================================================================


@pytest.mark.asyncio
async def test_safe_delete_and_undo_last_action_restores_file_intact(setup_env):
    """Verify that safe_delete followed by undo_last_action restores the file intact."""
    sandbox_dir = setup_env["sandbox_dir"]
    undo_dir = setup_env["undo_dir"]
    db_path = setup_env["db_path"]
    allowed_dirs = [sandbox_dir]

    # Create original test file
    test_file = sandbox_dir / "important_document.txt"
    original_content = "This is critical data that must be recoverable by the Undo Engine.\nLine 2: 12345."
    test_file.write_text(original_content, encoding="utf-8")
    assert test_file.exists()

    # 1. Execute safe_delete
    delete_result = await safe_delete(
        test_file,
        allowed_dirs=allowed_dirs,
        undo_dir=undo_dir,
        db_path=db_path,
    )
    assert delete_result["action_type"] == "delete"
    assert delete_result["undo_id"] > 0

    # Verify original file no longer exists at original location
    assert not test_file.exists()

    # Verify backup exists in undo storage
    backup_path = Path(delete_result["backup_path"])
    assert backup_path.exists()
    assert backup_path.read_text(encoding="utf-8") == original_content

    # 2. Execute undo_last_action
    undo_result = await undo_last_action(undo_dir=undo_dir, db_path=db_path)
    assert undo_result is not None
    assert undo_result["action_type"] == "delete"
    assert undo_result["restored"] is True

    # Verify file is restored intact with identical content
    assert test_file.exists()
    assert test_file.read_text(encoding="utf-8") == original_content

    # Subsequent undo should have nothing left to restore
    subsequent_undo = await undo_last_action(undo_dir=undo_dir, db_path=db_path)
    assert subsequent_undo is None


@pytest.mark.asyncio
async def test_safe_delete_and_undo_for_directory(setup_env):
    """Verify that directory safe_delete and undo works recursively."""
    sandbox_dir = setup_env["sandbox_dir"]
    undo_dir = setup_env["undo_dir"]
    db_path = setup_env["db_path"]
    allowed_dirs = [sandbox_dir]

    # Create folder structure
    folder = sandbox_dir / "my_project"
    folder.mkdir()
    f1 = folder / "main.py"
    f1.write_text("print('hello')", encoding="utf-8")
    sub = folder / "subfolder"
    sub.mkdir()
    f2 = sub / "util.py"
    f2.write_text("value = 42", encoding="utf-8")

    # Delete folder
    await safe_delete(folder, allowed_dirs=allowed_dirs, undo_dir=undo_dir, db_path=db_path)
    assert not folder.exists()

    # Undo
    undo_res = await undo_last_action(undo_dir=undo_dir, db_path=db_path)
    assert undo_res is not None
    assert folder.exists()
    assert (folder / "main.py").read_text(encoding="utf-8") == "print('hello')"
    assert (folder / "subfolder" / "util.py").read_text(encoding="utf-8") == "value = 42"


@pytest.mark.asyncio
async def test_safe_move_and_undo(setup_env):
    """Verify that safe_move can be undone cleanly."""
    sandbox_dir = setup_env["sandbox_dir"]
    undo_dir = setup_env["undo_dir"]
    db_path = setup_env["db_path"]
    allowed_dirs = [sandbox_dir]

    src_file = sandbox_dir / "draft.txt"
    src_content = "Draft version 1.0"
    src_file.write_text(src_content, encoding="utf-8")

    dst_file = sandbox_dir / "final.txt"

    # Move src to dst
    move_result = await safe_move(
        src_file,
        dst_file,
        allowed_dirs=allowed_dirs,
        undo_dir=undo_dir,
        db_path=db_path,
    )
    assert move_result["action_type"] == "move"
    assert not src_file.exists()
    assert dst_file.exists()
    assert dst_file.read_text(encoding="utf-8") == src_content

    # Undo move
    undo_res = await undo_last_action(undo_dir=undo_dir, db_path=db_path)
    assert undo_res is not None
    assert src_file.exists()
    assert src_file.read_text(encoding="utf-8") == src_content
    assert not dst_file.exists()


# =====================================================================
# 4. Database (Audit Log & Shortcuts) Tests
# =====================================================================


@pytest.mark.asyncio
async def test_audit_log_recording_and_retrieval(setup_env):
    """Verify audit log table stores and queries events correctly."""
    db_path = setup_env["db_path"]

    id1 = await db.log_audit("vitals", 1, "SUCCESS", "CPU: 12%", db_path=db_path)
    id2 = await db.log_audit("delete file.txt", 2, "PENDING", "Waiting for approval", db_path=db_path)
    id3 = await db.log_audit("reboot", 3, "BLOCKED", "PIN failed", db_path=db_path)

    assert id1 > 0
    assert id2 > id1
    assert id3 > id2

    logs = await db.get_audit_logs(limit=10, db_path=db_path)
    assert len(logs) == 3
    # Most recent first
    assert logs[0]["command"] == "reboot"
    assert logs[0]["tier"] == 3
    assert logs[0]["status"] == "BLOCKED"
    assert logs[1]["command"] == "delete file.txt"
    assert logs[2]["command"] == "vitals"


@pytest.mark.asyncio
async def test_shortcuts_crud(setup_env):
    """Verify shortcuts table operations."""
    db_path = setup_env["db_path"]

    # Add shortcuts
    await db.add_shortcut("status", "system_vitals", db_path=db_path)
    await db.add_shortcut("backup", "safe_backup_all", db_path=db_path)

    # Get shortcut (case-insensitive trigger)
    assert await db.get_shortcut("status", db_path=db_path) == "system_vitals"
    assert await db.get_shortcut("STATUS", db_path=db_path) == "system_vitals"
    assert await db.get_shortcut("unknown", db_path=db_path) is None

    # List shortcuts
    all_shortcuts = await db.list_shortcuts(db_path=db_path)
    assert len(all_shortcuts) == 2
    assert all_shortcuts["status"] == "system_vitals"

    # Remove shortcut
    assert await db.remove_shortcut("status", db_path=db_path) is True
    assert await db.get_shortcut("status", db_path=db_path) is None
    assert await db.remove_shortcut("status", db_path=db_path) is False


@pytest.mark.asyncio
async def test_default_sandbox_files_and_undo_cycle():
    """End-to-end test verifying default ./sandbox_files settings and operations."""
    settings = get_settings()
    sandbox = settings.ALLOWED_DIRS[0]
    sandbox.mkdir(parents=True, exist_ok=True)
    await db.init_db()

    # 1. Path traversal outside default sandbox raises PermissionError
    with pytest.raises(PermissionError):
        await safe_delete(sandbox / ".." / "evil.txt", allowed_dirs=[sandbox])

    # 2. Safe delete and undo in default sandbox
    test_file = sandbox / "live_phase1_test.txt"
    test_file.write_text("Default sandbox content test", encoding="utf-8")

    try:
        del_res = await safe_delete(test_file)
        assert not test_file.exists()

        undo_res = await undo_last_action()
        assert undo_res is not None
        assert test_file.exists()
        assert test_file.read_text(encoding="utf-8") == "Default sandbox content test"
    finally:
        if test_file.exists():
            test_file.unlink(missing_ok=True)

