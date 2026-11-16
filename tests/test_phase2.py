"""Tests for Phase 2: 4-Tier Permission Gate, System Tools, and Fast Router."""

import os
from pathlib import Path
import time
import pytest
import zipfile

from core import db
from core.permissions import (
    SecurityTier,
    check_forbidden_patterns,
    get_tool_tier,
    is_command_blocked,
)
from core.fast_router import ToolCall, route_command
from tools.system_tools import (
    capture_screenshot,
    find_files,
    get_system_vitals,
    resolve_file_for_sending,
    zip_and_prepare,
)


@pytest.fixture
async def setup_env(tmp_path):
    """Set up isolated sandbox and test database."""
    sandbox_dir = tmp_path / "sandbox_files"
    sandbox_dir.mkdir(parents=True, exist_ok=True)

    db_path = tmp_path / "test_phase2.db"
    await db.init_db(db_path)

    yield {
        "sandbox_dir": sandbox_dir,
        "db_path": db_path,
        "tmp_path": tmp_path,
    }


# =====================================================================
# 1. 4-Tier Permission Gate Tests
# =====================================================================


def test_permission_tier_registry_assignments():
    """Verify deterministic mapping of tools to base SecurityTier."""
    # Tier 1: Auto-Execute
    assert get_tool_tier("get_system_vitals") == SecurityTier.TIER_1_AUTO
    assert get_tool_tier("capture_screenshot") == SecurityTier.TIER_1_AUTO
    assert get_tool_tier("find_files") == SecurityTier.TIER_1_AUTO
    assert get_tool_tier("undo_last_action") == SecurityTier.TIER_1_AUTO
    assert get_tool_tier("list_shortcuts") == SecurityTier.TIER_1_AUTO

    # Tier 2: Confirmation Required
    assert get_tool_tier("safe_move") == SecurityTier.TIER_2_CONFIRM
    assert get_tool_tier("zip_and_prepare") == SecurityTier.TIER_2_CONFIRM
    assert get_tool_tier("start_service") == SecurityTier.TIER_2_CONFIRM
    assert get_tool_tier("stop_service") == SecurityTier.TIER_2_CONFIRM
    assert get_tool_tier("add_shortcut") == SecurityTier.TIER_2_CONFIRM

    # Tier 3: PIN Required
    assert get_tool_tier("safe_delete") == SecurityTier.TIER_3_PIN
    assert get_tool_tier("kill_process") == SecurityTier.TIER_3_PIN
    assert get_tool_tier("run_shell") == SecurityTier.TIER_3_PIN
    assert get_tool_tier("reboot_system") == SecurityTier.TIER_3_PIN

    # Tier 4: Hard-Blocked
    assert get_tool_tier("format_disk") == SecurityTier.TIER_4_BLOCKED
    assert get_tool_tier("edit_registry") == SecurityTier.TIER_4_BLOCKED
    assert get_tool_tier("disable_firewall") == SecurityTier.TIER_4_BLOCKED


def test_permission_regex_guard_blocks_forbidden_commands():
    """Verify regex guard scans arguments and enforces TIER_4_BLOCKED."""
    catastrophic_commands = [
        "format C:",
        "format /q D:",
        "regedit",
        "regedit.exe",
        "reg add HKLM\\Software\\Test",
        "reg delete HKCU\\Software\\Bad",
        "netsh advfirewall set allprofiles state off",
        "netsh advfirewall firewall add rule name=allow",
        "rm -rf /",
        "rm -rf /*",
        "rm -rf ~",
        "del /f /s /q C:\\*",
        "del /s /q /f important.sys",
        "rmdir /s /q C:\\Windows",
        "rd /s /q C:\\test",
        "bcdedit /set {default} recoveryenabled No",
        "vssadmin delete shadows /all /quiet",
        "diskpart",
        ":(){ :|:& };:",
    ]

    for cmd in catastrophic_commands:
        assert is_command_blocked(cmd) is True, f"Failed to block: {cmd}"
        # When passed into run_shell, it must be forced to Tier 4
        tier = get_tool_tier("run_shell", {"command": cmd})
        assert tier == SecurityTier.TIER_4_BLOCKED, f"Expected TIER_4_BLOCKED for: {cmd}"


def test_permission_safe_shell_commands_remain_tier_3():
    """Verify harmless shell commands are not false-positively blocked."""
    safe_commands = [
        "ls -la",
        "dir",
        "echo Hello World",
        "python --version",
        "git status",
        "cat package.json",
        "ipconfig /all",
    ]

    for cmd in safe_commands:
        assert is_command_blocked(cmd) is False
        assert get_tool_tier("run_shell", {"command": cmd}) == SecurityTier.TIER_3_PIN


# =====================================================================
# 2. Fast Router Deterministic Matching Tests
# =====================================================================


@pytest.mark.asyncio
async def test_fast_router_built_in_commands(setup_env):
    """Verify accurate deterministic routing of built-in commands."""
    db_path = setup_env["db_path"]

    # 1. Battery
    c1 = await route_command("battery", db_path=db_path)
    assert c1 is not None
    assert c1.tool_name == "get_system_vitals"
    assert c1.args.get("component") == "battery"
    assert c1.tier == SecurityTier.TIER_1_AUTO

    # 2. System info / status
    c2 = await route_command("/status", db_path=db_path)
    assert c2 is not None
    assert c2.tool_name == "get_system_vitals"
    assert c2.tier == SecurityTier.TIER_1_AUTO

    c2b = await route_command("system info", db_path=db_path)
    assert c2b is not None
    assert c2b.tool_name == "get_system_vitals"

    # 3. Screenshot
    c3 = await route_command("screenshot", db_path=db_path)
    assert c3 is not None
    assert c3.tool_name == "capture_screenshot"
    assert c3.tier == SecurityTier.TIER_1_AUTO

    # 4. Find file
    c4 = await route_command("find annual_report.pdf", db_path=db_path)
    assert c4 is not None
    assert c4.tool_name == "find_files"
    assert c4.args["query"] == "annual_report.pdf"
    assert c4.tier == SecurityTier.TIER_1_AUTO

    # 5. Delete file
    c5 = await route_command("delete old_logs.txt", db_path=db_path)
    assert c5 is not None
    assert c5.tool_name == "safe_delete"
    assert c5.args["target_path"] == "old_logs.txt"
    assert c5.tier == SecurityTier.TIER_3_PIN

    # 6. Move file
    c6 = await route_command("move file1.txt to file2.txt", db_path=db_path)
    assert c6 is not None
    assert c6.tool_name == "safe_move"
    assert c6.args["src"] == "file1.txt"
    assert c6.args["dst"] == "file2.txt"
    assert c6.tier == SecurityTier.TIER_2_CONFIRM

    # 7. Zip folder
    c7 = await route_command("zip my_project", db_path=db_path)
    assert c7 is not None
    assert c7.tool_name == "zip_and_prepare"
    assert c7.args["path"] == "my_project"
    assert c7.tier == SecurityTier.TIER_2_CONFIRM

    # 8. Undo
    c8 = await route_command("/undo", db_path=db_path)
    assert c8 is not None
    assert c8.tool_name == "undo_last_action"
    assert c8.tier == SecurityTier.TIER_1_AUTO

    # 9. Stop
    c9 = await route_command("/stop", db_path=db_path)
    assert c9 is not None
    assert c9.tool_name == "stop_service"
    assert c9.tier == SecurityTier.TIER_2_CONFIRM

    # 10. Reboot
    c10 = await route_command("reboot", db_path=db_path)
    assert c10 is not None
    assert c10.tool_name == "reboot_system"
    assert c10.tier == SecurityTier.TIER_3_PIN


@pytest.mark.asyncio
async def test_fast_router_blocks_tier_4_in_shell(setup_env):
    """Verify router automatically elevates destructive shell commands to TIER_4_BLOCKED."""
    db_path = setup_env["db_path"]

    # Harmless shell -> Tier 3
    safe_call = await route_command("run echo testing", db_path=db_path)
    assert safe_call is not None
    assert safe_call.tool_name == "run_shell"
    assert safe_call.tier == SecurityTier.TIER_3_PIN

    # Dangerous shell -> Tier 4
    blocked_call = await route_command("run format C:", db_path=db_path)
    assert blocked_call is not None
    assert blocked_call.tool_name == "run_shell"
    assert blocked_call.tier == SecurityTier.TIER_4_BLOCKED


@pytest.mark.asyncio
async def test_fast_router_resolves_shortcuts_first(setup_env):
    """Verify user-taught shortcuts are checked first and resolve instantly."""
    db_path = setup_env["db_path"]

    # Register user shortcuts
    await db.add_shortcut("shot", "screenshot", db_path=db_path)
    await db.add_shortcut("cleanup", "delete temporary.log", db_path=db_path)

    # Route using shortcut trigger
    call1 = await route_command("shot", db_path=db_path)
    assert call1 is not None
    assert call1.tool_name == "capture_screenshot"
    assert call1.tier == SecurityTier.TIER_1_AUTO

    call2 = await route_command("cleanup", db_path=db_path)
    assert call2 is not None
    assert call2.tool_name == "safe_delete"
    assert call2.args["target_path"] == "temporary.log"
    assert call2.tier == SecurityTier.TIER_3_PIN


@pytest.mark.asyncio
async def test_fast_router_returns_none_for_complex_requests(setup_env):
    """Verify complex, conversational, or multi-step requests bypass fast router to AI planner."""
    db_path = setup_env["db_path"]

    complex_prompts = [
        "Find all PDFs created last week and then zip them",
        "Why is my laptop running hot? Check top processes and explain",
        "Summarize the report in documents/summary.txt",
        "Search for receipts and also calculate total spend",
        "Can you write a python script to ping 8.8.8.8?",
    ]

    for prompt in complex_prompts:
        result = await route_command(prompt, db_path=db_path)
        assert result is None, f"Expected None for complex prompt: '{prompt}', got: {result}"


@pytest.mark.asyncio
async def test_fast_router_natural_phrasing(setup_env):
    """Verify natural language phrasing for common single-intent actions routes deterministically without LLM."""
    db_path = setup_env["db_path"]

    # Screenshots with natural phrasing
    screenshot_phrases = [
        "Give me the screenshot of pc",
        "send me the screenshot",
        "take a screenshot",
        "capture the screen",
        "please take a screenshot of my laptop",
        "desktop screenshot",
        "snap a screenshot",
    ]
    for phrase in screenshot_phrases:
        call = await route_command(phrase, db_path=db_path)
        assert call is not None, f"Failed to route screenshot phrase: '{phrase}'"
        assert call.tool_name == "capture_screenshot"
        assert call.tier == SecurityTier.TIER_1_AUTO

    # Battery with natural phrasing
    battery_phrases = [
        "what is the battery percentage",
        "check battery",
        "how is the battery of laptop",
        "show battery status",
    ]
    for phrase in battery_phrases:
        call = await route_command(phrase, db_path=db_path)
        assert call is not None, f"Failed to route battery phrase: '{phrase}'"
        assert call.tool_name == "get_system_vitals"
        assert call.args.get("component") == "battery"

    # Vitals with natural phrasing
    vitals_phrases = [
        "show vitals",
        "check system info",
        "how is the pc doing",
        "pc status",
        "laptop status",
    ]
    for phrase in vitals_phrases:
        call = await route_command(phrase, db_path=db_path)
        assert call is not None, f"Failed to route vitals phrase: '{phrase}'"
        assert call.tool_name == "get_system_vitals"

    # Send file with natural phrasing
    send_phrases = [
        ("In the download folder there is a file named mohammed_arshad_resume.pdf sent to me.", "mohammed_arshad_resume.pdf"),
        ("Send it to me.", "it"),
        ("In the download folder file named Mohammed_Arshad_Resume.pdf", "Mohammed_Arshad_Resume.pdf"),
        ("send mohammed_arshad_resume.pdf", "mohammed_arshad_resume.pdf"),
        ("send me the file report.pdf", "report.pdf"),
        ("download annual_report.pdf", "annual_report.pdf"),
        ("/send resume.pdf", "resume.pdf"),
    ]
    # Send file queries now drop regex and safely fall through to AIPlanner (call is None)
    for phrase, _ in send_phrases:
        call = await route_command(phrase, db_path=db_path)
        assert call is None, f"Expected send phrase to fall through to AIPlanner: '{phrase}'"


@pytest.mark.asyncio
async def test_fast_router_latency_under_5ms(setup_env):
    """Verify routing latency is consistently under 5ms."""
    db_path = setup_env["db_path"]

    # Warm-up run
    await route_command("status", db_path=db_path)

    commands = ["screenshot", "vitals", "battery", "/undo", "find test.txt", "stop"]
    latencies = []

    for cmd in commands:
        t0 = time.perf_counter()
        res = await route_command(cmd, db_path=db_path)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        latencies.append(elapsed_ms)
        assert res is not None

    avg_latency = sum(latencies) / len(latencies)
    assert avg_latency < 5.0, f"Average routing latency {avg_latency:.2f}ms exceeded 5ms limit!"


# =====================================================================
# 3. System Tools Functionality Tests
# =====================================================================


@pytest.mark.asyncio
async def test_system_vitals():
    """Verify get_system_vitals retrieves real psutil metrics."""
    vitals = await get_system_vitals()
    assert "cpu_percent" in vitals
    assert isinstance(vitals["cpu_percent"], (int, float))
    assert "ram" in vitals
    assert vitals["ram"]["total_gb"] > 0
    assert "disk" in vitals
    assert vitals["disk"]["total_gb"] > 0
    assert "battery" in vitals
    assert "formatted" in vitals
    assert "CPU:" in vitals["formatted"]


@pytest.mark.asyncio
async def test_capture_screenshot(setup_env):
    """Verify capture_screenshot outputs a valid PNG file."""
    output_dir = setup_env["tmp_path"] / "shots"
    shot_path = await capture_screenshot(output_dir=output_dir)
    assert shot_path.exists()
    assert shot_path.suffix.lower() == ".png"
    assert shot_path.stat().st_size > 0


@pytest.mark.asyncio
async def test_find_files_fuzzy_search(setup_env):
    """Verify rapidfuzz finds top 5 matching files inside allowed directories."""
    sandbox = setup_env["sandbox_dir"]

    # Create dummy files
    f1 = sandbox / "q3_financial_report.pdf"
    f1.write_text("dummy", encoding="utf-8")
    f2 = sandbox / "q4_financial_report.docx"
    f2.write_text("dummy", encoding="utf-8")
    f3 = sandbox / "recipe_lasagna.txt"
    f3.write_text("dummy", encoding="utf-8")
    sub = sandbox / "nested"
    sub.mkdir()
    f4 = sub / "report_summary.pdf"
    f4.write_text("dummy", encoding="utf-8")

    matches = await find_files("financial report", allowed_dirs=[sandbox], limit=5)
    assert len(matches) >= 2
    names = [m["name"] for m in matches]
    assert "q3_financial_report.pdf" in names
    assert "q4_financial_report.docx" in names
    assert "size_formatted" in matches[0]
    assert matches[0]["score"] >= matches[1]["score"]


@pytest.mark.asyncio
async def test_zip_and_prepare(setup_env):
    """Verify zip_and_prepare compresses directory inside allowed dirs."""
    sandbox = setup_env["sandbox_dir"]
    target_dir = sandbox / "bundle"
    target_dir.mkdir()
    (target_dir / "a.txt").write_text("File A", encoding="utf-8")
    (target_dir / "b.txt").write_text("File B", encoding="utf-8")

    zip_file = await zip_and_prepare(target_dir, allowed_dirs=[sandbox])
    assert zip_file.exists()
    assert zip_file.suffix == ".zip"

    # Verify contents of zip
    with zipfile.ZipFile(zip_file, "r") as zf:
        namelist = zf.namelist()
        assert any("a.txt" in n for n in namelist)
        assert any("b.txt" in n for n in namelist)


@pytest.mark.asyncio
async def test_resolve_file_for_sending(setup_env):
    """Verify resolve_file_for_sending resolves direct paths and fuzzy names inside allowed dirs."""
    sandbox = setup_env["sandbox_dir"]
    resume = sandbox / "Mohammed_Arshad_Resume.pdf"
    resume.write_text("dummy resume content", encoding="utf-8")

    # 1. Direct path
    p1 = await resolve_file_for_sending(resume, allowed_dirs=[sandbox])
    assert p1 == resume.resolve()

    # 2. Fuzzy filename search
    p2 = await resolve_file_for_sending("arshad resume", allowed_dirs=[sandbox])
    assert p2 == resume.resolve()

    # 3. Non-existent file raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        await resolve_file_for_sending("non_existent_file_xyz.pdf", allowed_dirs=[sandbox])

    # 4. Outside allowed dirs raises PermissionError
    outside_file = setup_env["tmp_path"] / "outside.txt"
    outside_file.write_text("outside", encoding="utf-8")
    with pytest.raises(PermissionError):
        await resolve_file_for_sending(outside_file, allowed_dirs=[sandbox])
