"""Tests for Phase 5: Developer Service Manager, Cloudflare Tunnels, and Sleep Prevention."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from core import db
from core.ai_planner import TOOL_SCHEMAS
from core.fast_router import route_command
from core.keep_awake import (
    disable_keep_awake,
    enable_keep_awake,
    is_keep_awake_enabled,
)
from core.permissions import SecurityTier, get_tool_tier
from tools.dev_services import (
    expose_port_tunnel,
    get_service_logs,
    list_running_services,
    load_services_registry,
    start_named_service,
    stop_named_service,
    RUNNING_SERVICES,
    RUNNING_TUNNELS,
)


@pytest.fixture(autouse=True)
def cleanup_phase5_state():
    """Clean up running services and tunnels between tests."""
    disable_keep_awake()
    RUNNING_SERVICES.clear()
    RUNNING_TUNNELS.clear()
    yield
    disable_keep_awake()
    for svc in list(RUNNING_SERVICES.keys()):
        try:
            asyncio.run(stop_named_service(svc))
        except Exception:
            pass
    RUNNING_SERVICES.clear()
    RUNNING_TUNNELS.clear()


@pytest.fixture
async def setup_env(tmp_path):
    """Set up isolated database and sandbox environment."""
    db_file = tmp_path / "test_phase5.db"
    await db.init_db(db_file)

    sandbox_dir = tmp_path / "sandbox_files"
    sandbox_dir.mkdir(parents=True, exist_ok=True)

    services_file = tmp_path / "services.json"
    services_config = {
        "dummy_worker": {
            "cwd": str(sandbox_dir),
            "cmd": ["python", "-c", "import time; time.sleep(60)"],
            "port": 9090,
            "description": "Background dummy worker",
        }
    }
    services_file.write_text(json.dumps(services_config, indent=2), encoding="utf-8")

    yield {
        "db_file": db_file,
        "tmp_path": tmp_path,
        "sandbox_dir": sandbox_dir,
        "services_file": services_file,
    }


# =====================================================================
# 1. Sleep Prevention (Keep Awake / Caffeinate) Tests
# =====================================================================


def test_keep_awake_lifecycle():
    """Verify enabling and disabling OS sleep prevention."""
    assert is_keep_awake_enabled() is False

    enabled = enable_keep_awake()
    assert enabled is True
    assert is_keep_awake_enabled() is True

    disabled = disable_keep_awake()
    assert disabled is True
    assert is_keep_awake_enabled() is False


# =====================================================================
# 2. Developer Service Manager Tests
# =====================================================================


@pytest.mark.asyncio
async def test_list_running_services():
    """Verify list_running_services inspects dev processes."""
    res = await list_running_services()
    assert "services" in res
    assert "count" in res
    assert "formatted" in res
    assert isinstance(res["services"], list)


@pytest.mark.asyncio
async def test_start_and_stop_named_service(setup_env):
    """Verify starting and gracefully terminating a background service."""
    services_file = setup_env["services_file"]

    # 1. Start service
    start_res = await start_named_service(
        "dummy_worker",
        services_file=services_file,
        allowed_dirs=[setup_env["sandbox_dir"]],
    )
    assert start_res["status"] == "started"
    assert start_res["service_name"] == "dummy_worker"
    assert start_res["pid"] > 0
    assert "dummy_worker" in RUNNING_SERVICES

    # 2. Starting again returns already_running
    dup_res = await start_named_service(
        "dummy_worker",
        services_file=services_file,
        allowed_dirs=[setup_env["sandbox_dir"]],
    )
    assert dup_res["status"] == "already_running"

    # 3. Retrieve service logs
    logs = get_service_logs("dummy_worker")
    assert isinstance(logs, str)

    # 4. Stop service
    stop_res = await stop_named_service("dummy_worker")
    assert stop_res["status"] == "stopped"
    assert "dummy_worker" not in RUNNING_SERVICES


@pytest.mark.asyncio
async def test_start_service_unknown_raises_key_error(setup_env):
    """Verify unknown service raises KeyError."""
    services_file = setup_env["services_file"]
    with pytest.raises(KeyError) as exc_info:
        await start_named_service("non_existent_app", services_file=services_file)
    assert "non_existent_app" in str(exc_info.value)


@pytest.mark.asyncio
async def test_start_service_outside_jail_raises_permission_error(setup_env):
    """Verify service with cwd outside allowed directories is blocked."""
    tmp_path = setup_env["tmp_path"]
    evil_file = tmp_path / "evil_services.json"
    forbidden_cwd = Path("C:/Windows/System32") if Path("C:/Windows/System32").exists() else Path("/etc")

    cfg = {
        "evil_app": {
            "cwd": str(forbidden_cwd),
            "cmd": ["python", "-c", "print('evil')"],
        }
    }
    evil_file.write_text(json.dumps(cfg), encoding="utf-8")

    with pytest.raises(PermissionError) as exc_info:
        await start_named_service("evil_app", services_file=evil_file)
    assert "outside allowed directories" in str(exc_info.value).lower()


# =====================================================================
# 3. Cloudflare Quick Tunnel Tests
# =====================================================================


@pytest.mark.asyncio
async def test_expose_port_tunnel_missing_binary():
    """Verify FileNotFoundError is raised when cloudflared binary is missing."""
    with patch("shutil.which", return_value=None):
        with pytest.raises(FileNotFoundError) as exc_info:
            await expose_port_tunnel(8000)
        assert "cloudflared" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_expose_port_tunnel_url_extraction():
    """Verify cloudflared stderr is parsed to extract trycloudflare.com URL."""
    sample_stderr = (
        b"2026-10-26T06:00:00Z INF Thank you for trying Cloudflare Tunnel!\n"
        b"2026-10-26T06:00:00Z INF |  Your quick Tunnel has been created! Visit it at:  |\n"
        b"2026-10-26T06:00:00Z INF |  https://brave-falcon-random123.trycloudflare.com  |\n"
    )

    mock_proc = MagicMock()
    mock_proc.pid = 44556

    mock_reader = AsyncMock()
    # Return sample lines then empty bytes
    mock_reader.readline = AsyncMock(side_effect=[
        b"2026-10-26T06:00:00Z INF Starting tunnel...\n",
        b"2026-10-26T06:00:00Z INF https://brave-falcon-random123.trycloudflare.com\n",
        b"",
    ])
    mock_proc.stderr = mock_reader

    with patch("shutil.which", return_value="C:\\fake\\cloudflared.exe"):
        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_proc)):
            res = await expose_port_tunnel(8080)
            assert res["status"] == "active"
            assert res["port"] == 8080
            assert res["url"] == "https://brave-falcon-random123.trycloudflare.com"
            assert f"`{res['url']}`" not in res["message"]
            assert res["url"] in res["message"]
            assert 8080 in RUNNING_TUNNELS


# =====================================================================
# 4. Fast Router & Permissions Phase 5 Tests
# =====================================================================


def test_permissions_tier_registry_phase5():
    """Verify Phase 5 tools have correct security tiers."""
    assert get_tool_tier("list_running_services") == SecurityTier.TIER_1_AUTO
    assert get_tool_tier("get_service_logs") == SecurityTier.TIER_1_AUTO
    assert get_tool_tier("caffeinate_status") == SecurityTier.TIER_1_AUTO

    assert get_tool_tier("start_named_service") == SecurityTier.TIER_2_CONFIRM
    assert get_tool_tier("stop_named_service") == SecurityTier.TIER_2_CONFIRM
    assert get_tool_tier("expose_port_tunnel") == SecurityTier.TIER_2_CONFIRM
    assert get_tool_tier("caffeinate_toggle") == SecurityTier.TIER_2_CONFIRM


@pytest.mark.asyncio
async def test_fast_router_phase5_commands(setup_env):
    """Verify built-in routing for Phase 5 commands."""
    db_file = setup_env["db_file"]

    # Services
    c1 = await route_command("services", db_path=db_file)
    assert c1 is not None
    assert c1.tool_name == "list_running_services"
    assert c1.tier == SecurityTier.TIER_1_AUTO

    # Start service
    c2 = await route_command("start fastapi_demo", db_path=db_file)
    assert c2 is not None
    assert c2.tool_name == "start_named_service"
    assert c2.args["service_name"] == "fastapi_demo"
    assert c2.tier == SecurityTier.TIER_2_CONFIRM

    # Stop service
    c3 = await route_command("stop_service fastapi_demo", db_path=db_file)
    assert c3 is not None
    assert c3.tool_name == "stop_named_service"
    assert c3.args["service_name"] == "fastapi_demo"
    assert c3.tier == SecurityTier.TIER_2_CONFIRM

    # Tunnel
    c4 = await route_command("tunnel 8000", db_path=db_file)
    assert c4 is not None
    assert c4.tool_name == "expose_port_tunnel"
    assert c4.args["port"] == 8000
    assert c4.tier == SecurityTier.TIER_2_CONFIRM

    # Caffeinate
    c5 = await route_command("/caffeinate on", db_path=db_file)
    assert c5 is not None
    assert c5.tool_name == "caffeinate_toggle"
    assert c5.args["state"] == "on"
    assert c5.tier == SecurityTier.TIER_2_CONFIRM

    c6 = await route_command("/caffeinate", db_path=db_file)
    assert c6 is not None
    assert c6.tool_name == "caffeinate_status"
    assert c6.tier == SecurityTier.TIER_1_AUTO


def test_ai_planner_phase5_tool_schemas():
    """Verify Phase 5 tools are declared in AI Planner TOOL_SCHEMAS."""
    tool_names = [t["function"]["name"] for t in TOOL_SCHEMAS]
    assert "list_running_services" in tool_names
    assert "start_named_service" in tool_names
    assert "stop_named_service" in tool_names
    assert "expose_port_tunnel" in tool_names


@pytest.mark.asyncio
async def test_project_inspector_deterministic_detection(setup_env):
    """Verify project_inspector automatically discovers FastAPI backends and Vite frontends."""
    from core import project_inspector

    env = setup_env
    sandbox = env["sandbox_dir"]
    proj = sandbox / "mock_quant_app"
    proj.mkdir()

    # 1. Setup backend
    b_dir = proj / "backend"
    b_dir.mkdir()
    (b_dir / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\nport = 8080", encoding="utf-8")
    b_venv = b_dir / "venv" / "Scripts"
    b_venv.mkdir(parents=True)
    b_py = b_venv / "python.exe"
    b_py.write_text("# dummy python", encoding="utf-8")

    # 2. Setup frontend
    f_dir = proj / "frontend"
    f_dir.mkdir()
    (f_dir / "package.json").write_text('{"name": "mock-ui", "scripts": {"dev": "vite"}}', encoding="utf-8")
    (f_dir / "vite.config.js").write_text("// dummy vite config", encoding="utf-8")

    # Test detection of backend
    spec_b, all_comps, _ = project_inspector.resolve_service_to_start("mock_quant_app", "backend", allowed_dirs=[sandbox])
    assert spec_b is not None
    assert spec_b.component == "backend"
    assert spec_b.stack == "FastAPI / Python"
    assert spec_b.port == 8080
    assert spec_b.cwd == b_dir.resolve()

    # Test detection of frontend
    spec_f, all_comps, _ = project_inspector.resolve_service_to_start("mock_quant_app", "frontend", allowed_dirs=[sandbox])
    assert spec_f is not None
    assert spec_f.component == "frontend"
    assert spec_f.stack == "React (Vite)"
    assert spec_f.port == 5173
    assert spec_f.cwd == f_dir.resolve()
    assert spec_f.cmd[-2:] == ["--", "--host"]

    # Test router component parsing
    c_b = await route_command("start the backend of mock_quant_app", db_path=env["db_file"])
    assert c_b is not None
    assert c_b.tool_name == "start_named_service"
    assert c_b.args["service_name"] == "mock_quant_app"
    assert c_b.args["component"] == "backend"

    c_f = await route_command("launch mock_quant_app frontend", db_path=env["db_file"])
    assert c_f is not None
    assert c_f.tool_name == "start_named_service"
    assert c_f.args["service_name"] == "mock_quant_app"
    assert c_f.args["component"] == "frontend"


@pytest.mark.asyncio
async def test_folder_files_routing_and_packaging(setup_env, tmp_path):
    """Test deterministic routing and packaging for folder batch requests."""
    env = setup_env
    sandbox = env["sandbox_dir"]

    # Test router drops regex and safely falls through to AIPlanner
    r1 = await route_command("Give me all the images in the folder D_drive\\princess_aayu", db_path=env["db_file"])
    assert r1 is None

    r2 = await route_command("Send me all the images in the folder D_drive\\princess_aayu", db_path=env["db_file"])
    assert r2 is None

    # Create dummy folder with images and docs
    img_folder = sandbox / "Princess Aayu"
    img_folder.mkdir(parents=True, exist_ok=True)
    (img_folder / "pic1.jpg").write_bytes(b"image data 1")
    (img_folder / "pic2.png").write_bytes(b"image data 2")
    (img_folder / "notes.txt").write_text("some text")

    from tools import system_tools

    # Test package_folder_files with category='images'
    pkg = await system_tools.package_folder_files(
        "princess_aayu",
        category="images",
        allowed_dirs=[sandbox],
        output_dir=tmp_path / "zips",
    )
    assert pkg["file_count"] == 2
    assert pkg["category"] == "images"
    assert pkg["zip_path"].is_file()
    assert len(pkg["sample_files"]) == 2

    # Test sentence query false positive prevention in find_files
    matches = await system_tools.find_files(
        "all the images in the folder D_drive\\princess_aayu",
        allowed_dirs=[sandbox],
    )
    # Should not match notes.txt or pic1.jpg with high score
    assert not any(m["score"] >= 80.0 for m in matches)
