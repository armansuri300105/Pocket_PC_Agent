"""Tests for Phase 6: Token Optimization & Qwen Tool-Call Resilience."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest

from bot.telegram_gateway import (
    ACTIVE_DIR_SESSIONS,
    ACTIVE_FILE_BUTTONS,
    FILES_PER_PAGE,
    build_dir_keyboard,
    build_explore_inline_keyboard,
    execute_tool_call,
    handle_pagination_callback,
    handle_sendfile_callback,
    handle_text_message,
    handle_zipdir_callback,
    register_file_button,
)
from core import db
from core.ai_planner import (
    AIPlanner,
    ANALYTICAL_KEYWORDS,
    DEV_TOOL_SCHEMAS,
    FILE_TOOL_SCHEMAS,
    SYS_TOOL_SCHEMAS,
    TERMINAL_TOOLS,
    TOOL_SCHEMAS,
    PlannerResult,
    compress_tool_output,
    parse_inline_tool_call,
    recover_failed_tool_call,
    select_relevant_tools,
)
from core.config import get_settings
from core.fast_router import ToolCall, route_command, route_command_chain
from core.permissions import SecurityTier
from core.smart_resolver import SmartFileResolver
from tools import dev_services, system_tools
from tools.system_tools import explore_path, deliver_path, list_directory


@pytest.fixture
async def setup_env(tmp_path):
    """Set up isolated database and sandbox environment for Phase 6 tests."""
    db_file = tmp_path / "test_phase6.db"
    await db.init_db(db_file)

    sandbox_dir = tmp_path / "sandbox_files"
    sandbox_dir.mkdir(parents=True, exist_ok=True)

    sample_doc = sandbox_dir / "annual_report.pdf"
    sample_doc.write_text("dummy report content")

    return {
        "db_file": db_file,
        "sandbox_dir": sandbox_dir,
        "tmp_path": tmp_path,
    }


# =====================================================================
# 1. Minified & Partitioned Tool Schemas + select_relevant_tools
# =====================================================================


def test_select_relevant_tools_filtering_and_fallback():
    """Verify tool descriptions <= 25 words, bucket filtering, and ambiguous query fallback."""
    # 1. Verify all tool descriptions <= 25 words
    assert len(TOOL_SCHEMAS) == 19
    for schema in TOOL_SCHEMAS:
        fn = schema["function"]
        desc = fn["description"]
        word_count = len(desc.split())
        assert word_count <= 25, f"Tool {fn['name']} description exceeded 25 words ({word_count}): '{desc}'"

    # 2. File bucket keyword matching
    file_tools = select_relevant_tools("find my annual_report.pdf")
    file_tool_names = {t["function"]["name"] for t in file_tools}
    assert "explore_path" in file_tool_names
    assert "deliver_path" in file_tool_names
    assert "safe_delete" in file_tool_names
    assert "safe_move" in file_tool_names
    assert "undo_last_action" in file_tool_names
    # Dev and Sys tools should not be included
    assert "list_running_services" not in file_tool_names
    assert "capture_screenshot" not in file_tool_names

    # 3. Dev bucket keyword matching
    dev_tools = select_relevant_tools("start backend service")
    dev_tool_names = {t["function"]["name"] for t in dev_tools}
    assert "start_named_service" in dev_tool_names
    assert "list_running_services" in dev_tool_names
    assert "safe_delete" not in dev_tool_names

    # 4. System bucket keyword matching
    sys_tools = select_relevant_tools("check cpu vitals and memory")
    sys_tool_names = {t["function"]["name"] for t in sys_tools}
    assert "get_system_vitals" in sys_tool_names
    assert "capture_screenshot" in sys_tool_names
    assert "explore_path" not in sys_tool_names

    # 5. Multi-bucket union matching
    mixed_tools = select_relevant_tools("inspect directory and start service")
    mixed_tool_names = {t["function"]["name"] for t in mixed_tools}
    assert "explore_path" in mixed_tool_names
    assert "start_named_service" in mixed_tool_names

    # 6. Fallback: completely ambiguous prompt returns all 19 schemas
    fallback_tools = select_relevant_tools("what is the philosophical meaning of existence")
    assert len(fallback_tools) == 19
    assert {t["function"]["name"] for t in fallback_tools} == {t["function"]["name"] for t in TOOL_SCHEMAS}


# =====================================================================
# 2. Zero-Token 400 tool_use_failed Recovery
# =====================================================================


def test_recover_failed_tool_call_from_400_payload():
    """Verify tool calls are recovered from Qwen XML or markdown JSON error payloads with int coercion."""
    # 1. Qwen XML format with <think> reasoning trace and stringified port
    qwen_payload = {
        "error": {
            "message": "tool_use_failed",
            "failed_generation": (
                "<think>\n"
                "The user wants to expose local port 8000 using Cloudflare tunnel.\n"
                "I should call expose_port_tunnel.\n"
                "</think>\n"
                "<tool_call>\n"
                '{"name": "expose_port_tunnel", "arguments": {"port": "8000"}}\n'
                "</tool_call>"
            ),
        }
    }
    recovered = recover_failed_tool_call(qwen_payload)
    assert recovered is not None
    assert recovered.tool_name == "expose_port_tunnel"
    assert recovered.args == {"port": 8000}  # stringified port coerced to int
    assert recovered.tier == SecurityTier.TIER_2_CONFIRM

    # 2. Markdown fenced JSON payload
    fenced_payload = {
        "failed_generation": (
            "```json\n"
            '{"name": "find_files", "arguments": {"query": "annual_report.pdf"}}\n'
            "```"
        )
    }
    recovered2 = recover_failed_tool_call(fenced_payload)
    assert recovered2 is not None
    assert recovered2.tool_name == "explore_path"
    assert recovered2.args == {"query": "annual_report.pdf"}
    assert recovered2.tier == SecurityTier.TIER_1_AUTO

    # 3. Direct JSON string payload
    raw_str_payload = '{"failed_generation": "<tool_call>{\\"name\\": \\"get_system_vitals\\", \\"arguments\\": {\\"component\\": \\"cpu\\"}}\\n</tool_call>"}'
    recovered3 = recover_failed_tool_call(raw_str_payload)
    assert recovered3 is not None
    assert recovered3.tool_name == "get_system_vitals"
    assert recovered3.args == {"component": "cpu"}
    assert recovered3.tier == SecurityTier.TIER_1_AUTO

    # 4. Strict Security Invariant: Tier 4 is preserved on recovered tool call
    evil_payload = {
        "failed_generation": '<tool_call>{"name": "run_shell", "arguments": {"command": "format C:"}}</tool_call>'
    }
    recovered4 = recover_failed_tool_call(evil_payload)
    assert recovered4 is not None
    assert recovered4.tool_name == "run_shell"
    assert recovered4.tier == SecurityTier.TIER_4_BLOCKED

    # 5. Non-tool error payload returns None
    assert recover_failed_tool_call({"error": "Model overloaded"}) is None
    assert recover_failed_tool_call("") is None


@pytest.mark.asyncio
async def test_400_recovery_end_to_end_in_planner(setup_env):
    """Verify that plan_and_execute handles HTTP 400 tool_use_failed seamlessly without retrying."""
    planner = AIPlanner()

    # 1. Test terminal tool 400 recovery (e.g. capture_screenshot) which short-circuits immediately
    req = httpx.Request("POST", "http://localhost:11434/v1/chat/completions")
    resp_400_terminal = httpx.Response(
        status_code=400,
        request=req,
        json={
            "error": {
                "message": "tool_use_failed",
                "failed_generation": (
                    "<think>Need screenshot</think>\n"
                    "<tool_call>{\"name\": \"capture_screenshot\", \"arguments\": {}}</tool_call>"
                ),
            }
        },
    )

    with patch.object(planner, "_call_llm", side_effect=httpx.HTTPStatusError("tool_use_failed", request=req, response=resp_400_terminal)):
        result_terminal = await planner.plan_and_execute("take a screenshot")
        assert result_terminal.completed is True
        assert len(result_terminal.executed_steps) == 1
        assert result_terminal.executed_steps[0].tool_name == "capture_screenshot"
        assert "Screenshot saved" in result_terminal.final_message

    # 2. Test non-terminal tool 400 recovery followed by synthesis step
    resp_400_vitals = httpx.Response(
        status_code=400,
        request=req,
        json={
            "error": {
                "message": "tool_use_failed",
                "failed_generation": (
                    "<think>Thinking</think>\n"
                    "<tool_call>{\"name\": \"get_system_vitals\", \"arguments\": {\"component\": \"cpu\"}}</tool_call>"
                ),
            }
        },
    )
    synthesis_resp = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Your CPU usage is currently normal.",
                }
            }
        ]
    }

    mock_llm = AsyncMock(side_effect=[
        httpx.HTTPStatusError("tool_use_failed", request=req, response=resp_400_vitals),
        synthesis_resp,
    ])

    with patch.object(planner, "_call_llm", new=mock_llm):
        result = await planner.plan_and_execute("Check my CPU")

        assert result.completed is True
        assert len(result.executed_steps) == 1
        assert result.executed_steps[0].tool_name == "get_system_vitals"
        assert "CPU usage is currently normal" in result.final_message
        assert result.session_messages[-1]["role"] == "tool"



# =====================================================================
# 3. Terminal Tool Short-Circuit & Tool-Free Synthesis
# =====================================================================


@pytest.mark.asyncio
async def test_terminal_tool_short_circuit_skips_second_llm_call(setup_env):
    """Verify executing a terminal tool without analytical verbs returns immediately with 1 LLM call."""
    planner = AIPlanner()

    mock_terminal_response = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_shot",
                            "type": "function",
                            "function": {
                                "name": "capture_screenshot",
                                "arguments": "{}",
                            },
                        }
                    ],
                }
            }
        ]
    }

    with patch.object(planner, "_call_llm", new=AsyncMock(return_value=mock_terminal_response)) as mock_call:
        # Non-analytical user prompt: "take a screenshot"
        result = await planner.plan_and_execute("take a screenshot")

        # Terminal tool short-circuits: exactly 1 call to LLM, 0 second calls!
        assert mock_call.call_count == 1
        assert result.completed is True
        assert len(result.executed_steps) == 1
        assert result.executed_steps[0].tool_name == "capture_screenshot"
        assert "Screenshot saved successfully" in result.final_message


@pytest.mark.asyncio
async def test_resume_after_approval_terminal_tool_short_circuit(setup_env):
    """Verify resume_after_approval with a terminal tool skips any follow-up LLM calls."""
    planner = AIPlanner()

    paused_tc = ToolCall(
        tool_name="start_named_service",
        args={"service_name": "trading_agent"},
        tier=SecurityTier.TIER_2_CONFIRM,
    )
    from core.ai_planner import PlannerResult
    paused_result = PlannerResult(
        completed=False,
        paused_for_approval=True,
        paused_tool_call=paused_tc,
        paused_call_id="call_start",
        session_messages=[
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "start trading_agent"},
        ],
        step_count=1,
    )

    with patch.object(planner, "_call_llm", new=AsyncMock()) as mock_call:
        res = await planner.resume_after_approval(paused_result, "Service trading_agent started on port 8000")
        assert res.completed is True
        assert res.final_message == "Service trading_agent started on port 8000"
        # 0 calls made to LLM!
        assert mock_call.call_count == 0


@pytest.mark.asyncio
async def test_analytical_prompt_calls_synthesis_with_tools_none(setup_env):
    """Verify analytical prompts proceed to text synthesis with tools=None to save tokens."""
    planner = AIPlanner()

    mock_tool_step = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_vitals",
                            "type": "function",
                            "function": {
                                "name": "get_system_vitals",
                                "arguments": json.dumps({"component": "cpu"}),
                            },
                        }
                    ],
                }
            }
        ]
    }
    mock_synthesis_step = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Your CPU usage is currently at 12%.",
                }
            }
        ]
    }

    mock_llm = AsyncMock(side_effect=[mock_tool_step, mock_synthesis_step])
    with patch.object(planner, "_call_llm", new=mock_llm):
        # Prompt contains analytical verb "tell me"
        result = await planner.plan_and_execute("check vitals and tell me how my cpu is doing")

        assert result.completed is True
        assert "12%" in result.final_message
        assert mock_llm.call_count == 2

        # Check that the second synthesis call passed tools=None to save input tokens!
        second_call_kwargs = mock_llm.call_args_list[1]
        passed_tools = second_call_kwargs[1].get("tools") if "tools" in second_call_kwargs[1] else (
            second_call_kwargs[0][1] if len(second_call_kwargs[0]) > 1 else None
        )
        assert passed_tools is None


# =====================================================================
# 4. Deterministic Conjunction Splitting in Fast Router
# =====================================================================


@pytest.mark.asyncio
async def test_fast_router_command_chain_deterministic_split(setup_env):
    """Verify conjunction splitting across multiple independent commands and contextual fallback."""
    db_path = setup_env["db_file"]

    # 1. Independent two-step command chain
    chain1 = await route_command_chain("screenshot and then status", db_path=db_path)
    assert chain1 is not None
    assert len(chain1) == 2
    assert chain1[0].tool_name == "capture_screenshot"
    assert chain1[1].tool_name == "get_system_vitals"

    # 2. Different conjunction phrasing: 'then'
    chain2 = await route_command_chain("take a screenshot then vitals", db_path=db_path)
    assert chain2 is not None
    assert len(chain2) == 2
    assert chain2[0].tool_name == "capture_screenshot"
    assert chain2[1].tool_name == "get_system_vitals"

    # 3. Different conjunction phrasing: 'after that'
    chain3 = await route_command_chain("services after that caffeinate on", db_path=db_path)
    assert chain3 is not None
    assert len(chain3) == 2
    assert chain3[0].tool_name == "list_running_services"
    assert chain3[1].tool_name == "caffeinate_toggle"

    # 4. Contextual reference returns None so AI Planner resolves context
    assert await route_command_chain("find resume.pdf and then send it", db_path=db_path) is None
    assert await route_command_chain("find report.pdf after that delete it", db_path=db_path) is None
    assert await route_command_chain("zip my_project and then send them", db_path=db_path) is None

    # 5. Unknown clause returns None so AI Planner handles it
    assert await route_command_chain("screenshot and then write a poem about rust", db_path=db_path) is None

    # 6. Backward compatibility: route_command returns None for conjunctions
    assert await route_command("screenshot and then status", db_path=db_path) is None


# =====================================================================
# 5. Relative Path Compression in Planner Tool Outputs
# =====================================================================


def test_relative_path_compression_in_planner_messages(setup_env):
    """Verify absolute paths are stripped from ALLOWED_DIRS and long outputs truncated to 600 chars."""
    sandbox_dir = setup_env["sandbox_dir"]
    raw_path = str(sandbox_dir / "annual_report.pdf")

    # Output containing absolute path
    raw_output = f'Found files: [{{"name": "annual_report.pdf", "path": "{raw_path}"}}]'

    compressed = compress_tool_output(raw_output, allowed_dirs=[sandbox_dir], max_len=600)

    # Absolute path prefix must be stripped
    assert str(sandbox_dir) not in compressed
    assert "annual_report.pdf" in compressed

    # Truncation verification
    long_raw_output = "X" * 1200
    compressed_long = compress_tool_output(long_raw_output, allowed_dirs=[sandbox_dir], max_len=600)
    assert len(compressed_long) <= 600

    # Secret scrubbing integration
    secret_output = "Database password was DB_PASSWORD=my_secret_token_12345 in output"
    scrubbed = compress_tool_output(secret_output, allowed_dirs=[sandbox_dir], max_len=600)
    assert "my_secret_token_12345" not in scrubbed
    assert "[REDACTED_SECRET]" in scrubbed


# =====================================================================
# 6. Universal Tools, SmartFileResolver & Qwen XML Parsing
# =====================================================================


@pytest.mark.asyncio
async def test_smart_resolver_d_drive_root_mapping(setup_env, tmp_path):
    """Verify SmartFileResolver.resolve('d_drive') correctly maps to the root without getting lost in deep subfolders."""
    # 1. Setup mock root directory named 'd_drive'
    d_drive_root = tmp_path / "d_drive"
    d_drive_root.mkdir(parents=True, exist_ok=True)

    # 2. Setup deep nested subfolders also containing 'd_drive'
    deep_nested = d_drive_root / "deep" / "nested" / "d_drive"
    deep_nested.mkdir(parents=True, exist_ok=True)
    (deep_nested / "sub_doc.txt").write_text("deep secret")

    resolver = SmartFileResolver.get_instance()
    resolver.clear_index()

    # Build index on allowed dir
    await resolver.build_index(allowed_dirs=[d_drive_root])

    # 3. Resolve 'd_drive' -> must resolve to root d_drive, NOT deep nested
    resolved_root = resolver.resolve("d_drive", allowed_dirs=[d_drive_root])
    assert resolved_root == d_drive_root.resolve()
    assert resolved_root != deep_nested.resolve()

    # Also resolve case variations
    assert resolver.resolve("D_Drive", allowed_dirs=[d_drive_root]) == d_drive_root.resolve()
    assert resolver.resolve("d drive", allowed_dirs=[d_drive_root]) == d_drive_root.resolve()


@pytest.mark.asyncio
async def test_explore_path_files_and_directories_dynamic(setup_env):
    """Verify explore_path correctly handles both files and directories dynamically."""
    sandbox_dir = setup_env["sandbox_dir"]
    tmp_path = setup_env["tmp_path"]

    # Create subfolders and files
    subfolder = sandbox_dir / "project_alpha"
    subfolder.mkdir(exist_ok=True)
    (subfolder / "config.json").write_text('{"app": 1}')
    (sandbox_dir / "notes.txt").write_text("my notes")

    resolver = SmartFileResolver.get_instance()
    resolver.clear_index()
    await resolver.build_index(allowed_dirs=[sandbox_dir])

    # 1. Dynamic directory exploration
    dir_res = await explore_path("project_alpha", allowed_dirs=[sandbox_dir])
    assert dir_res["type"] == "directory"
    assert dir_res["name"] == "project_alpha"
    assert "config.json" in dir_res["files"]
    assert "project_alpha" in dir_res["formatted"]

    # 2. Dynamic file exploration
    file_res = await explore_path("notes.txt", allowed_dirs=[sandbox_dir])
    assert file_res["type"] == "file"
    assert file_res["name"] == "notes.txt"
    assert "size" in file_res
    assert Path(file_res["path"]).resolve() == (sandbox_dir / "notes.txt").resolve()

    # 3. Directory jail enforcement
    outside_dir = tmp_path / "outside_jail"
    outside_dir.mkdir(exist_ok=True)
    with pytest.raises(PermissionError):
        await explore_path(str(outside_dir), allowed_dirs=[sandbox_dir])


@pytest.mark.asyncio
async def test_daemon_startup_triggers_build_index_non_blocking():
    """Ensure the daemon startup successfully triggers build_index() without blocking the main event loop."""
    mock_bot_instance = MagicMock()
    mock_bot_instance.session.close = AsyncMock()

    with patch("core.smart_resolver.SmartFileResolver.build_index", new=AsyncMock()) as mock_build:
        with patch("main.db.init_db", new=AsyncMock()), \
             patch("main.ensure_sandbox_fixtures", return_value=Path(".")), \
             patch("main.load_services_registry"), \
             patch("main.keep_awake"), \
             patch("main.setup_dispatcher") as mock_setup_dp, \
             patch("main.Bot", return_value=mock_bot_instance), \
             patch("main.get_settings") as mock_settings:

            settings_obj = MagicMock()
            settings_obj.TELEGRAM_BOT_TOKEN = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
            settings_obj.OWNER_TELEGRAM_ID = 12345678
            settings_obj.ALLOWED_DIRS = [Path(".")]
            settings_obj.UNDO_DIR = Path("./.undo_storage")
            settings_obj.DATABASE_PATH = Path("./test.db")
            mock_settings.return_value = settings_obj

            mock_dp = MagicMock()
            mock_dp.start_polling = AsyncMock(return_value=None)
            mock_dp.resolve_used_update_types = MagicMock(return_value=[])
            mock_setup_dp.return_value = mock_dp

            from main import main
            await main()

            mock_build.assert_called_once()


@pytest.mark.asyncio
async def test_fast_router_file_queries_fall_through_to_planner(setup_env):
    """Verify file/folder queries drop brittle regex and safely fall through to AIPlanner (returns None)."""
    db_path = setup_env["db_file"]

    # File and directory queries must return None from fast_router
    assert await route_command("list all the folder name present in D_drive/projects", db_path=db_path) is None
    assert await route_command("list all folders in sandbox_files", db_path=db_path) is None
    assert await route_command("show folders in D_drive/projects", db_path=db_path) is None
    assert await route_command("what folders are in D_drive/projects", db_path=db_path) is None
    assert await route_command("ls D_drive/projects", db_path=db_path) is None
    assert await route_command("send annual_report.pdf", db_path=db_path) is None
    assert await route_command("send me all the images in the folder photos", db_path=db_path) is None


@pytest.mark.asyncio
async def test_parse_qwen_xml_tool_call_in_content(setup_env):
    """Verify Qwen XML tool calls inside message.content are intercepted and executed without raw XML leaking."""
    planner = AIPlanner()

    raw_qwen_xml = (
        "<tool_call>\n"
        "<function=explore_path>\n"
        "<parameter=target>\n"
        "D_drive/projects\n"
        "</parameter>\n"
        "</function>\n"
        "</tool_call>"
    )

    # 1. Verify parse_inline_tool_call correctly extracts tool name and args
    parsed = parse_inline_tool_call(raw_qwen_xml)
    assert parsed is not None
    tool_name, tool_args = parsed
    assert tool_name == "explore_path"
    assert tool_args == {"target": "D_drive/projects"}

    # 2. Verify AIPlanner intercepts it from message.content, executes, and prevents XML leak
    mock_msg = {
        "role": "assistant",
        "content": raw_qwen_xml,
    }
    mock_response = {
        "choices": [
            {"message": mock_msg}
        ]
    }

    mock_dir_result = {
        "type": "directory",
        "name": "projects",
        "path": "D_drive/projects",
        "folders": ["pocket_pc_agent", "trading_agent"],
        "files": [],
        "formatted": "📂 Directory: projects\n\n📁 Folders (2):\n• pocket_pc_agent\n• trading_agent",
    }

    with patch.object(planner, "_call_llm", new=AsyncMock(return_value=mock_response)):
        with patch("tools.system_tools.explore_path", new=AsyncMock(return_value=mock_dir_result)):
            result = await planner.plan_and_execute("list all the folder name present in D_drive/projects")

            assert result.completed is True
            # Zero XML leaks to user!
            assert "<tool_call>" not in result.final_message
            assert "<function=" not in result.final_message
            assert "pocket_pc_agent" in result.final_message
            assert len(result.executed_steps) == 1
            assert result.executed_steps[0].tool_name == "explore_path"


# =====================================================================
# 7. Inline Download Buttons for explore_path
# =====================================================================


@pytest.mark.asyncio
async def test_inline_button_generation_on_explore_path(setup_env):
    """Verify inline download buttons with Send All (Zip) and pagination are generated when explore_path returns files."""
    sandbox_dir = setup_env["sandbox_dir"]

    # 1. Test build_explore_inline_keyboard with multiple files
    mock_res = {
        "type": "directory",
        "name": "resume",
        "path": str(sandbox_dir),
        "folders": [],
        "files": ["resume_v1.pdf", "resume_v2.pdf", "portfolio.pdf"],
    }
    keyboard = build_explore_inline_keyboard(mock_res)
    assert keyboard is not None
    # Row 1 is Zip, Rows 2-4 are the 3 files -> 4 rows
    assert len(keyboard.inline_keyboard) == 4

    # Row 0: Bulk Action [📦 Send All (Zip)]
    zip_btn = keyboard.inline_keyboard[0][0]
    assert zip_btn.text == "📦 Send All (Zip)"
    assert zip_btn.callback_data.startswith("zipdir:")

    # Row 1: First file button
    btn0 = keyboard.inline_keyboard[1][0]
    assert btn0.text == "📥 resume_v1.pdf"
    assert btn0.callback_data.startswith("sendfile:")

    # 2. Test filename truncation if > 30 characters
    mock_long = {
        "type": "directory",
        "name": "long_docs",
        "path": str(sandbox_dir),
        "folders": [],
        "files": ["this_is_a_very_long_filename_that_exceeds_thirty_characters_indeed.pdf"],
    }
    long_kb = build_explore_inline_keyboard(mock_long)
    assert long_kb is not None
    long_btn = long_kb.inline_keyboard[1][0]
    assert len(long_btn.text.replace("📥 ", "")) <= 30

    # 3. Test pagination: 15 files -> 1 zip row + 8 file rows + 1 pagination row = 10 rows
    mock_many = {
        "type": "directory",
        "name": "many_files",
        "path": str(sandbox_dir),
        "folders": [],
        "files": [f"file_{i}.txt" for i in range(15)],
    }
    many_kb = build_explore_inline_keyboard(mock_many)
    assert many_kb is not None
    assert len(many_kb.inline_keyboard) == 10
    # Check Row 9 pagination controls
    nav_row = many_kb.inline_keyboard[9]
    assert "1 / 2" in nav_row[0].text
    assert nav_row[0].callback_data == "ignore"
    assert "Next" in nav_row[1].text
    assert nav_row[1].callback_data.startswith("page:")

    # 4. Test directory with no files returns None
    mock_empty = {
        "type": "directory",
        "name": "empty",
        "path": str(sandbox_dir),
        "folders": ["subfolder"],
        "files": [],
    }
    assert build_explore_inline_keyboard(mock_empty) is None

    # 5. Test non-directory returns None
    mock_file = {
        "type": "file",
        "name": "single.txt",
        "path": str(sandbox_dir / "single.txt"),
    }
    assert build_explore_inline_keyboard(mock_file) is None

    # 6. Test integration with handle_text_message
    mock_bot = AsyncMock()
    mock_message = MagicMock()
    mock_message.text = "Sent me the file present in sandbox_files"
    mock_message.from_user.id = 12345678
    mock_message.chat.id = 12345678
    mock_message.answer = AsyncMock()

    planner_res_mock = PlannerResult(
        completed=True,
        final_message="📂 Directory: sandbox_files\n• annual_report.pdf",
        executed_steps=[
            ToolCall(
                tool_name="explore_path",
                args={"target": "sandbox_files"},
                tier=SecurityTier.TIER_1_AUTO,
            )
        ],
    )

    with patch("bot.telegram_gateway.get_settings") as mock_settings, \
         patch("bot.telegram_gateway.AIPlanner") as mock_planner_cls:
        settings_obj = MagicMock()
        settings_obj.OWNER_TELEGRAM_ID = 12345678
        settings_obj.ALLOWED_DIRS = [sandbox_dir]
        mock_settings.return_value = settings_obj

        planner_inst = MagicMock()
        planner_inst.plan_and_execute = AsyncMock(return_value=planner_res_mock)
        mock_planner_cls.return_value = planner_inst

        await handle_text_message(mock_message, mock_bot)

        assert mock_message.answer.call_count == 2
        _, kwargs = mock_message.answer.call_args
        attached_kb = kwargs.get("reply_markup")
        assert attached_kb is not None
        assert len(attached_kb.inline_keyboard) >= 1
        assert attached_kb.inline_keyboard[0][0].callback_data.startswith("zipdir:")


@pytest.mark.asyncio
async def test_sendfile_callback_handling_and_security(setup_env):
    """Verify handle_sendfile_callback delivers file and securely handles invalid or outside paths."""
    sandbox_dir = setup_env["sandbox_dir"]
    test_file = sandbox_dir / "annual_report.pdf"

    short_id = register_file_button(test_file)
    mock_bot = AsyncMock()

    # 1. Valid short_id delivery
    valid_callback = MagicMock()
    valid_callback.data = f"sendfile:{short_id}"
    valid_callback.from_user.id = 12345678
    valid_callback.message.chat.id = 12345678
    valid_callback.answer = AsyncMock()

    with patch("core.sandbox.get_settings") as mock_settings:
        settings_obj = MagicMock()
        settings_obj.ALLOWED_DIRS = [sandbox_dir]
        mock_settings.return_value = settings_obj

        await handle_sendfile_callback(valid_callback, mock_bot)
        valid_callback.answer.assert_called_with("Sending file...")
        mock_bot.send_document.assert_called_once()

    # 2. Invalid or expired short_id returns safe fallback message
    invalid_callback = MagicMock()
    invalid_callback.data = "sendfile:expired_id_123"
    invalid_callback.from_user.id = 12345678
    invalid_callback.message.chat.id = 12345678
    invalid_callback.answer = AsyncMock()

    await handle_sendfile_callback(invalid_callback, mock_bot)
    invalid_callback.answer.assert_called_with("File is no longer available or was moved.", show_alert=True)

    # 3. Security Invariant: Path outside ALLOWED_DIRS is securely rejected
    outside_file = setup_env["tmp_path"] / "outside.txt"
    outside_file.write_text("evil outside data")
    outside_id = register_file_button(outside_file)

    jail_callback = MagicMock()
    jail_callback.data = f"sendfile:{outside_id}"
    jail_callback.from_user.id = 12345678
    jail_callback.message.chat.id = 12345678
    jail_callback.answer = AsyncMock()

    with patch("core.sandbox.get_settings") as mock_settings:
        settings_obj = MagicMock()
        settings_obj.ALLOWED_DIRS = [sandbox_dir]  # outside_file is NOT in sandbox_dir
        mock_settings.return_value = settings_obj

        await handle_sendfile_callback(jail_callback, mock_bot)
        jail_callback.answer.assert_called_with(
            "Access denied: File is outside allowed directories or does not exist.",
            show_alert=True,
        )


# =====================================================================
# 8. LLM Self-Correction for Unknown Tools & Prevention of PIN Prompts
# =====================================================================


@pytest.mark.asyncio
async def test_ai_planner_self_corrects_unknown_tool(setup_env):
    """Verify planner intercepts unknown tools, feeds error back to LLM, and never pauses for PIN approval."""
    planner = AIPlanner()

    # Part 1: Structured tool call with unknown name ('invalid_tool')
    mock_unknown_structured = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_bad_1",
                            "type": "function",
                            "function": {
                                "name": "invalid_tool",
                                "arguments": json.dumps({"target": "notes.txt"}),
                            },
                        }
                    ],
                }
            }
        ]
    }

    mock_corrected_step = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "I realized 'invalid_tool' does not exist and have completed your request.",
                }
            }
        ]
    }

    mock_llm = AsyncMock(side_effect=[mock_unknown_structured, mock_corrected_step])

    with patch.object(planner, "_call_llm", new=mock_llm):
        result = await planner.plan_and_execute("Find notes.txt")

        # Crucial security invariant: Must NEVER pause for approval / PIN on unknown tool!
        assert result.paused_for_approval is False
        assert result.completed is True
        assert mock_llm.call_count == 2

        # Verify error message was recorded in session messages for LLM self-correction
        tool_err_messages = [
            m for m in result.session_messages
            if m.get("role") == "tool" and "does not exist" in m.get("content", "")
        ]
        assert len(tool_err_messages) == 1
        err_msg = tool_err_messages[0]
        assert err_msg["tool_call_id"] == "call_bad_1"
        assert err_msg["name"] == "invalid_tool"
        assert "Error: Tool 'invalid_tool' does not exist." in err_msg["content"]
        assert "explore_path, deliver_path" in err_msg["content"]

    # Part 2: Inline XML unknown tool (e.g., truncated/hallucinated '<function=exp>')
    mock_unknown_inline = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "<tool_call><function=exp><parameter=target>notes.txt</parameter></function></tool_call>",
                }
            }
        ]
    }

    mock_valid_inline_correction = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Completed self correction after exp failed.",
                }
            }
        ]
    }

    mock_llm_inline = AsyncMock(side_effect=[mock_unknown_inline, mock_valid_inline_correction])

    with patch.object(planner, "_call_llm", new=mock_llm_inline):
        result2 = await planner.plan_and_execute("Explore notes")

        assert result2.paused_for_approval is False
        assert result2.completed is True
        assert mock_llm_inline.call_count == 2

        inline_err_msgs = [
            m for m in result2.session_messages
            if m.get("role") == "tool" and "does not exist" in m.get("content", "")
        ]
        assert len(inline_err_msgs) == 1
        assert "Error: Tool 'exp' does not exist." in inline_err_msgs[0]["content"]


# =====================================================================
# 9. Inline Pagination & "Send All as Zip" for explore_path
# =====================================================================


@pytest.mark.asyncio
async def test_inline_pagination_logic(setup_env):
    """Verify build_dir_keyboard correctly slices 32 files into 4 pages of 8 buttons each with bulk zip and pagination."""
    sandbox_dir = setup_env["sandbox_dir"]
    session_id = "test_sess_32"

    # Create 32 mock files on filesystem inside sandbox
    test_folder = sandbox_dir / "Princess_Aayu"
    test_folder.mkdir(parents=True, exist_ok=True)
    file_list = []
    for i in range(32):
        f = test_folder / f"photo_{i:02d}.jpg"
        f.write_text(f"dummy data {i}")
        file_list.append(f.name)

    ACTIVE_DIR_SESSIONS[session_id] = {
        "dir_path": str(test_folder.resolve()),
        "files": file_list,
        "page": 0,
    }

    # -------------------------------------------------------------
    # Page 0 (Files 0..7)
    # -------------------------------------------------------------
    kb0 = build_dir_keyboard(session_id, page=0)
    assert kb0 is not None
    # 1 zip row + 8 file rows + 1 pagination row = 10 rows
    assert len(kb0.inline_keyboard) == 10

    # Row 0: Send All (Zip)
    assert kb0.inline_keyboard[0][0].text == "📦 Send All (Zip)"
    assert kb0.inline_keyboard[0][0].callback_data == f"zipdir:{session_id}"

    # Rows 1..8: 8 files
    for idx in range(8):
        btn = kb0.inline_keyboard[idx + 1][0]
        assert btn.text == f"📥 photo_{idx:02d}.jpg"
        assert btn.callback_data == f"sendfile:{session_id}:{idx}"

    # Row 9: Pagination controls (No Prev button on Page 0)
    nav0 = kb0.inline_keyboard[9]
    assert len(nav0) == 2
    assert "1 / 4" in nav0[0].text
    assert nav0[0].callback_data == "ignore"
    assert "Next" in nav0[1].text
    assert nav0[1].callback_data == f"page:{session_id}:1"

    # -------------------------------------------------------------
    # Page 1 (Files 8..15)
    # -------------------------------------------------------------
    kb1 = build_dir_keyboard(session_id, page=1)
    assert kb1 is not None
    assert len(kb1.inline_keyboard) == 10
    assert kb1.inline_keyboard[0][0].text == "📦 Send All (Zip)"

    for idx in range(8):
        global_idx = 8 + idx
        btn = kb1.inline_keyboard[idx + 1][0]
        assert btn.text == f"📥 photo_{global_idx:02d}.jpg"
        assert btn.callback_data == f"sendfile:{session_id}:{global_idx}"

    nav1 = kb1.inline_keyboard[9]
    assert len(nav1) == 3
    assert "Prev" in nav1[0].text
    assert nav1[0].callback_data == f"page:{session_id}:0"
    assert "2 / 4" in nav1[1].text
    assert nav1[1].callback_data == "ignore"
    assert "Next" in nav1[2].text
    assert nav1[2].callback_data == f"page:{session_id}:2"

    # -------------------------------------------------------------
    # Page 2 (Files 16..23)
    # -------------------------------------------------------------
    kb2 = build_dir_keyboard(session_id, page=2)
    assert kb2 is not None
    assert len(kb2.inline_keyboard) == 10
    nav2 = kb2.inline_keyboard[9]
    assert len(nav2) == 3
    assert nav2[0].callback_data == f"page:{session_id}:1"
    assert "3 / 4" in nav2[1].text
    assert nav2[2].callback_data == f"page:{session_id}:3"

    # -------------------------------------------------------------
    # Page 3 (Files 24..31 - Final Page)
    # -------------------------------------------------------------
    kb3 = build_dir_keyboard(session_id, page=3)
    assert kb3 is not None
    assert len(kb3.inline_keyboard) == 10
    for idx in range(8):
        global_idx = 24 + idx
        btn = kb3.inline_keyboard[idx + 1][0]
        assert btn.text == f"📥 photo_{global_idx:02d}.jpg"
        assert btn.callback_data == f"sendfile:{session_id}:{global_idx}"

    nav3 = kb3.inline_keyboard[9]
    assert len(nav3) == 2  # Prev + counter (No Next on last page)
    assert "Prev" in nav3[0].text
    assert nav3[0].callback_data == f"page:{session_id}:2"
    assert "4 / 4" in nav3[1].text

    # -------------------------------------------------------------
    # Test Pagination Callback Interaction
    # -------------------------------------------------------------
    mock_cb_page = MagicMock()
    mock_cb_page.data = f"page:{session_id}:1"
    mock_cb_page.answer = AsyncMock()
    mock_cb_page.message = MagicMock()
    mock_cb_page.message.edit_reply_markup = AsyncMock()

    await handle_pagination_callback(mock_cb_page)
    mock_cb_page.answer.assert_called_once()
    mock_cb_page.message.edit_reply_markup.assert_called_once()

    # -------------------------------------------------------------
    # Test Send File Callback with session format
    # -------------------------------------------------------------
    mock_cb_file = MagicMock()
    mock_cb_file.data = f"sendfile:{session_id}:5"
    mock_cb_file.from_user.id = 12345678
    mock_cb_file.message.chat.id = 12345678
    mock_cb_file.answer = AsyncMock()
    mock_bot = AsyncMock()

    with patch("core.sandbox.get_settings") as mock_settings:
        settings_obj = MagicMock()
        settings_obj.ALLOWED_DIRS = [sandbox_dir]
        mock_settings.return_value = settings_obj

        await handle_sendfile_callback(mock_cb_file, mock_bot)
        mock_cb_file.answer.assert_called_with("Sending file...")
        mock_bot.send_document.assert_called_once()
        _, send_kwargs = mock_bot.send_document.call_args
        assert "photo_05.jpg" in send_kwargs.get("caption", "")

    # -------------------------------------------------------------
    # Test Send All Zip Callback
    # -------------------------------------------------------------
    mock_cb_zip = MagicMock()
    mock_cb_zip.data = f"zipdir:{session_id}"
    mock_cb_zip.from_user.id = 12345678
    mock_cb_zip.message.chat.id = 12345678
    mock_cb_zip.answer = AsyncMock()
    mock_zip_bot = AsyncMock()

    with patch("core.sandbox.get_settings") as mock_sandbox_settings, \
         patch("core.smart_resolver.get_settings") as mock_resolver_settings, \
         patch("tools.system_tools.get_settings") as mock_sys_settings:
        settings_obj = MagicMock()
        settings_obj.ALLOWED_DIRS = [sandbox_dir]
        settings_obj.UNDO_DIR = sandbox_dir / ".undo_storage"
        mock_sandbox_settings.return_value = settings_obj
        mock_resolver_settings.return_value = settings_obj
        mock_sys_settings.return_value = settings_obj

        await handle_zipdir_callback(mock_cb_zip, mock_zip_bot)
        mock_cb_zip.answer.assert_called_with("Bundling directory as zip...")
        mock_zip_bot.send_document.assert_called_once()
        _, zip_kwargs = mock_zip_bot.send_document.call_args
        assert "Delivered:" in zip_kwargs.get("caption", "")
        assert ".zip" in zip_kwargs.get("caption", "")


# =====================================================================
# 10. Local Antivirus Resilience & Graceful Subprocess Handling
# =====================================================================


@pytest.mark.asyncio
async def test_expose_port_tunnel_oserror_av_block():
    """Verify expose_port_tunnel catches OSError/PermissionError and returns clear AV block warning."""
    with patch("shutil.which", return_value="C:\\fake\\cloudflared.exe"):
        with patch("asyncio.create_subprocess_exec", side_effect=OSError("[WinError 5] Access is denied")):
            res = await dev_services.expose_port_tunnel(8888)

            assert res["status"] == "error"
            assert "Windows Defender or local Antivirus may have blocked or quarantined" in res["message"]


@pytest.mark.asyncio
async def test_run_shell_oserror_av_block():
    """Verify run_shell catches OSError/PermissionError and returns clear AV block warning."""
    with patch("asyncio.create_subprocess_shell", side_effect=PermissionError("Operation blocked by OS")):
        res = await system_tools.run_shell("dir")

        assert res["status"] == "error"
        assert "Shell execution denied by the operating system. Check local Antivirus/Defender logs." in res["message"]


@pytest.mark.asyncio
async def test_ai_planner_graceful_av_reporting(setup_env):
    """Verify AI Planner receives AV error as normal tool output and summarizes gracefully without 500 error."""
    planner = AIPlanner()

    mock_tool_step = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_tunnel_1",
                            "type": "function",
                            "function": {
                                "name": "expose_port_tunnel",
                                "arguments": json.dumps({"port": 8000}),
                            },
                        }
                    ],
                }
            }
        ]
    }

    mock_summary_step = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Windows Defender appears to have blocked cloudflared.exe.",
                }
            }
        ]
    }

    mock_llm = AsyncMock(side_effect=[mock_tool_step, mock_summary_step])

    with patch.object(planner, "_call_llm", new=mock_llm):
        with patch("shutil.which", return_value="C:\\fake\\cloudflared.exe"):
            with patch("asyncio.create_subprocess_exec", side_effect=OSError("Access denied")):
                # The user prompt contains "tell me" to trigger synthesis after terminal tool
                result = await planner.plan_and_execute("expose port 8000 and tell me the result")

                # Deterministic Permission Gate: Tier 2 Confirmation is strictly retained
                assert result.paused_for_approval is True
                assert result.paused_tool_call.tool_name == "expose_port_tunnel"
                assert result.paused_tool_call.tier == SecurityTier.TIER_2_CONFIRM

                # Upon user confirmation, execute_tool_locally runs and catches AV block gracefully
                from core.ai_planner import execute_tool_locally
                tool_out = await execute_tool_locally(
                    result.paused_tool_call.tool_name,
                    result.paused_tool_call.args,
                )
                assert "Windows Defender or local Antivirus may have blocked" in tool_out

                # Resumed planning completes with error output fed back to LLM
                resumed = await planner.resume_after_approval(result, tool_out)
                assert resumed.completed is True
                assert "Windows Defender" in resumed.final_message
                tool_msg = [m for m in resumed.session_messages if m.get("role") == "tool"][0]
                assert "Windows Defender or local Antivirus may have blocked" in tool_msg["content"]


@pytest.mark.asyncio
async def test_start_service_from_path_resolution(setup_env):
    """Verify passing a fuzzy path like 'trading_agent' resolves via SmartFileResolver, inspects stack, and starts service."""
    sandbox = setup_env["sandbox_dir"]
    trading_dir = sandbox / "Trading_agent"
    trading_dir.mkdir(parents=True, exist_ok=True)

    # Create dummy FastAPI project entrypoint that runs briefly
    entry = trading_dir / "main.py"
    entry.write_text(
        "import time\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "port = 8099\n"
        "time.sleep(5)\n",
        encoding="utf-8",
    )

    services_file = setup_env["tmp_path"] / "test_services.json"
    services_file.write_text("{}", encoding="utf-8")

    from core.smart_resolver import SmartFileResolver
    from tools.dev_services import RUNNING_SERVICES, start_named_service, stop_named_service

    # Clear resolver index so newly created directory is discovered
    SmartFileResolver.get_instance().clear_index()

    start_res = await start_named_service(
        target="trading_agent",
        services_file=services_file,
        allowed_dirs=[sandbox],
    )

    assert start_res["status"] == "started"
    assert "trading_agent" in start_res["service_name"]
    assert start_res["pid"] > 0
    assert start_res["service_name"] in RUNNING_SERVICES

    # Verify auto-saved to services.json
    saved_registry = json.loads(services_file.read_text(encoding="utf-8"))
    assert start_res["service_name"] in saved_registry

    # Clean up background process
    stop_res = await stop_named_service(start_res["service_name"])
    assert stop_res["status"] == "stopped"
    assert start_res["service_name"] not in RUNNING_SERVICES


@pytest.mark.asyncio
async def test_kill_process_permission_and_execution():
    """Verify kill_process routes to Tier 3 PIN, executes via psutil, and handles NoSuchProcess gracefully."""
    import psutil
    from core.permissions import SecurityTier, get_tool_tier
    from tools.system_tools import kill_process

    # 1. Non-negotiable security invariant: Tier 3 PIN
    assert get_tool_tier("kill_process", {"pid": 6332}) == SecurityTier.TIER_3_PIN
    assert get_tool_tier("kill_process", {"target": "6332"}) == SecurityTier.TIER_3_PIN

    # 2. Mock psutil.Process to simulate NoSuchProcess
    with patch("psutil.Process", side_effect=psutil.NoSuchProcess(pid=99999)):
        res = await kill_process(99999)
        assert res["status"] == "error"
        assert "not found" in res["message"].lower() or "does not exist" in res["message"].lower()

    # 3. Mock psutil.Process to simulate AccessDenied
    with patch("psutil.Process", side_effect=psutil.AccessDenied(pid=1)):
        res_denied = await kill_process(1)
        assert res_denied["status"] == "error"
        assert "access denied" in res_denied["message"].lower()

    # 4. Mock psutil.Process for successful termination
    mock_proc = MagicMock()
    mock_proc.name.return_value = "dummy_server.exe"
    mock_proc.children.return_value = []
    mock_proc.terminate.return_value = None

    with patch("psutil.Process", return_value=mock_proc):
        with patch("psutil.wait_procs", return_value=([mock_proc], [])):
            res_ok = await kill_process(6332)
            assert res_ok["status"] == "success"
            assert res_ok["pid"] == 6332
            assert "dummy_server.exe" in res_ok["name"]
            mock_proc.terminate.assert_called_once()

    # 5. Fast router routes "Stop the service run at PID 6332" to kill_process with Tier 3
    from core.fast_router import route_command
    call = await route_command("Stop the service run at PID 6332")
    assert call is not None
    assert call.tool_name == "kill_process"
    assert call.args["pid"] == 6332
    assert call.tier == SecurityTier.TIER_3_PIN


@pytest.mark.asyncio
async def test_safe_delete_uses_smart_resolver(setup_env):
    """Verify passing a fuzzy filename like '1.docx' or 'the file named 1.docx' maps via SmartFileResolver and stages deletion."""
    sandbox = setup_env["sandbox_dir"]
    downloads_dir = sandbox / "Downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)

    target_file = downloads_dir / "1.docx"
    target_file.write_text("sample document content", encoding="utf-8")

    undo_dir = setup_env["tmp_path"] / "undo_storage"
    undo_dir.mkdir(parents=True, exist_ok=True)
    db_file = setup_env["db_file"]

    from core.smart_resolver import SmartFileResolver
    from core.sandbox import safe_delete, safe_move

    # Clear index cache to discover newly created file
    SmartFileResolver.get_instance().clear_index()

    # 1. Delete using conversational string "the file named 1.docx"
    del_res = await safe_delete(
        "the file named 1.docx",
        allowed_dirs=[sandbox],
        undo_dir=undo_dir,
        db_path=db_file,
    )

    assert del_res["status"] == "success"
    assert del_res["action_type"] == "delete"
    assert Path(del_res["original_path"]).resolve() == target_file.resolve()
    assert not target_file.exists()
    assert Path(del_res["backup_path"]).exists()
    assert Path(del_res["backup_path"]).read_text(encoding="utf-8") == "sample document content"

    # 2. Non-existent file returns clean error dict
    err_res = await safe_delete(
        "non_existent_random_file_xyz.txt",
        allowed_dirs=[sandbox],
        undo_dir=undo_dir,
        db_path=db_file,
    )
    assert err_res["status"] == "error"
    assert "could not locate" in err_res["message"].lower()

    # 3. Test safe_move with conversational prefix and relative path
    kuro_file = downloads_dir / "kuro.pdf"
    kuro_file.write_text("kuro pdf data", encoding="utf-8")
    SmartFileResolver.get_instance().clear_index()

    move_res = await safe_move(
        "the file named kuro.pdf",
        "renamed_kuro.pdf",
        allowed_dirs=[sandbox],
        undo_dir=undo_dir,
        db_path=db_file,
    )
    assert move_res["status"] == "success"
    assert move_res["action_type"] == "move"
    assert not kuro_file.exists()
    assert Path(move_res["destination_path"]).exists()
    assert Path(move_res["destination_path"]).read_text(encoding="utf-8") == "kuro pdf data"


@pytest.mark.asyncio
async def test_smart_resolver_composite_path(setup_env):
    """Verify SmartFileResolver composite path parsing:
    1. Resolves 'Downloads/1.docx' to the exact file.
    2. Resolving 'Downloads/invalid_file.txt' raises FileNotFoundError instead of returning the Downloads folder.
    3. Trailing slashes like 'Downloads/' and 'Downloads\\' normalize to the directory itself.
    """
    sandbox = setup_env["sandbox_dir"]
    downloads_dir = sandbox / "Downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)

    docx_file = downloads_dir / "1.docx"
    docx_file.write_text("dummy docx content", encoding="utf-8")

    from core.smart_resolver import SmartFileResolver
    resolver = SmartFileResolver.get_instance()
    resolver.clear_index()

    # 1. Resolving exact composite path identifies file
    res_file = resolver.resolve("Downloads/1.docx", allowed_dirs=[sandbox])
    assert res_file == docx_file.resolve()
    assert res_file.is_file()

    # 2. Resolving invalid file in existing folder raises FileNotFoundError (does not return folder)
    with pytest.raises(FileNotFoundError) as exc_info:
        resolver.resolve("Downloads/invalid_file.txt", allowed_dirs=[sandbox])
    assert "Downloads" in str(exc_info.value)
    assert "invalid_file.txt" in str(exc_info.value)

    # 3. Trailing slashes normalize to folder
    res_dir_fwd = resolver.resolve("Downloads/", allowed_dirs=[sandbox])
    assert res_dir_fwd == downloads_dir.resolve()
    assert res_dir_fwd.is_dir()

    res_dir_back = resolver.resolve("Downloads\\", allowed_dirs=[sandbox])
    assert res_dir_back == downloads_dir.resolve()
    assert res_dir_back.is_dir()


@pytest.mark.asyncio
async def test_stop_named_service_kills_tunnel():
    """Verify passing 'tunnel 8000' to stop_named_service targets RUNNING_TUNNELS and terminates process tree."""
    from tools.dev_services import RUNNING_TUNNELS, stop_named_service

    mock_proc = MagicMock()
    mock_proc.pid = 44444
    mock_proc.returncode = None
    mock_proc.kill = MagicMock()

    RUNNING_TUNNELS[8000] = {
        "port": 8000,
        "url": "https://test-tunnel.trycloudflare.com",
        "pid": 44444,
        "proc": mock_proc,
    }

    mock_child = MagicMock()
    mock_parent = MagicMock()
    mock_parent.children.return_value = [mock_child]

    with patch("psutil.Process", return_value=mock_parent) as mock_psutil_proc, \
         patch("psutil.wait_procs", return_value=([mock_child, mock_parent], [])):
        res = await stop_named_service("tunnel 8000")

        assert res["status"] == "success"
        assert "Successfully stopped Cloudflare tunnel on port 8000" in res["message"]
        assert 8000 not in RUNNING_TUNNELS

        mock_psutil_proc.assert_called_with(44444)
        mock_child.terminate.assert_called_once()
        mock_parent.terminate.assert_called_once()

    # Verify attempting to stop again returns not_running
    res_not_running = await stop_named_service("tunnel 8000")
    assert res_not_running["status"] == "not_running"


@pytest.mark.asyncio
async def test_tier_2_resume_no_double_output(setup_env):
    """Verify that approving a paused Tier 2 action in AI Planner does not emit double output."""
    from aiogram.types import CallbackQuery
    from bot.telegram_gateway import (
        PENDING_APPROVALS,
        PENDING_PLANNER_SESSIONS,
        handle_approve_callback,
    )
    from core.ai_planner import AIPlanner, PlannerResult
    from core.fast_router import ToolCall
    from core.permissions import SecurityTier

    owner_id = get_settings().OWNER_TELEGRAM_ID
    paused_tc = ToolCall(
        tool_name="expose_port_tunnel",
        args={"port": 8000},
        tier=SecurityTier.TIER_2_CONFIRM,
    )
    approval_id = "test_appr_123"
    PENDING_APPROVALS[approval_id] = paused_tc

    planner = AIPlanner()
    paused_result = PlannerResult(
        completed=False,
        paused_for_approval=True,
        paused_tool_call=paused_tc,
        paused_call_id="call_tunnel",
        session_messages=[
            {"role": "user", "content": "expose port 8000"},
        ],
        step_count=1,
    )
    PENDING_PLANNER_SESSIONS[owner_id] = (planner, paused_result)

    callback = MagicMock(spec=CallbackQuery)
    callback.data = f"approve:{approval_id}"
    callback.from_user = MagicMock(id=owner_id)
    callback.message = MagicMock()
    callback.message.edit_text = AsyncMock()
    callback.answer = AsyncMock()

    mock_bot = MagicMock()
    mock_bot.send_message = AsyncMock()

    with patch("bot.telegram_gateway.execute_tool_locally", new=AsyncMock(return_value="🔗 Live Cloudflare Tunnel:\nhttps://abc.trycloudflare.com")) as mock_exec_local, \
         patch("bot.telegram_gateway.execute_tool_call", new=AsyncMock()) as mock_exec_tc:
        await handle_approve_callback(callback, mock_bot)

        # execute_tool_call should NOT be called (which would have caused double message)
        mock_exec_tc.assert_not_called()
        mock_exec_local.assert_called_once_with("expose_port_tunnel", {"port": 8000})

        # bot.send_message should be called exactly ONCE with the planner's final message
        assert mock_bot.send_message.call_count == 1
        sent_text = mock_bot.send_message.call_args[0][1]
        assert "https://abc.trycloudflare.com" in sent_text


@pytest.mark.asyncio
async def test_fast_router_strips_emojis(setup_env):
    """Verify that leading emojis on UI buttons are stripped so fast_router routes without AI planner."""
    from core.fast_router import route_command, route_command_chain
    from core.permissions import SecurityTier

    db_file = setup_env["db_file"]

    # 1. 📸 Screenshot -> capture_screenshot (Tier 1)
    call_shot = await route_command("📸 Screenshot", db_path=db_file)
    assert call_shot is not None
    assert call_shot.tool_name == "capture_screenshot"
    assert call_shot.tier == SecurityTier.TIER_1_AUTO

    # 2. 📊 Status -> get_system_vitals (Tier 1)
    call_status = await route_command("📊 Status", db_path=db_file)
    assert call_status is not None
    assert call_status.tool_name == "get_system_vitals"
    assert call_status.tier == SecurityTier.TIER_1_AUTO

    # 3. 📋 Services -> list_running_services (Tier 1)
    call_services = await route_command("📋 Services", db_path=db_file)
    assert call_services is not None
    assert call_services.tool_name == "list_running_services"
    assert call_services.tier == SecurityTier.TIER_1_AUTO

    # 4. ☕ Caffeinate -> caffeinate_status (Tier 1)
    call_caff = await route_command("☕ Caffeinate", db_path=db_file)
    assert call_caff is not None
    assert call_caff.tool_name == "caffeinate_status"
    assert call_caff.tier == SecurityTier.TIER_1_AUTO

    # 5. ↩️ Undo -> undo_last_action (Tier 1)
    call_undo = await route_command("↩️ Undo", db_path=db_file)
    assert call_undo is not None
    assert call_undo.tool_name == "undo_last_action"
    assert call_undo.tier == SecurityTier.TIER_1_AUTO

    # 6. Conjunction chain with emojis
    chain = await route_command_chain("📸 Screenshot and then 📊 Status", db_path=db_file)
    assert chain is not None
    assert len(chain) == 2
    assert chain[0].tool_name == "capture_screenshot"
    assert chain[1].tool_name == "get_system_vitals"


@pytest.mark.asyncio
async def test_ai_planner_rejects_empty_arguments(setup_env):
    """Verify planner catches None/empty arguments on tools with required parameters, appends error, and loops without pausing."""
    planner = AIPlanner()

    # Step 1: Model emits stop_named_service with None arguments
    mock_malformed_step = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_malformed_1",
                            "type": "function",
                            "function": {
                                "name": "stop_named_service",
                                "arguments": None,
                            },
                        }
                    ],
                }
            }
        ]
    }

    # Step 2: Model self-corrects with a text response
    mock_corrected_step = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "I apologize, I forgot to specify the service name to stop.",
                }
            }
        ]
    }

    mock_llm = AsyncMock(side_effect=[mock_malformed_step, mock_corrected_step])

    with patch.object(planner, "_call_llm", new=mock_llm):
        result = await planner.plan_and_execute("stop the service")

        # Must NOT pause for user approval on malformed arguments!
        assert result.paused_for_approval is False
        assert result.completed is True
        assert mock_llm.call_count == 2

        # Verify exact error message was appended to session_messages
        tool_err_messages = [
            m for m in result.session_messages
            if m.get("role") == "tool" and "failed to provide the required arguments" in m.get("content", "")
        ]
        assert len(tool_err_messages) == 1
        err_msg = tool_err_messages[0]
        assert err_msg["tool_call_id"] == "call_malformed_1"
        assert err_msg["name"] == "stop_named_service"
        assert "You called 'stop_named_service' but failed to provide the required arguments" in err_msg["content"]

    # Also test empty dictionary "{}"
    mock_empty_dict_step = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_malformed_2",
                            "type": "function",
                            "function": {
                                "name": "start_named_service",
                                "arguments": "{}",
                            },
                        }
                    ],
                }
            }
        ]
    }
    mock_llm_empty = AsyncMock(side_effect=[mock_empty_dict_step, mock_corrected_step])
    with patch.object(planner, "_call_llm", new=mock_llm_empty):
        result2 = await planner.plan_and_execute("start the service")
        assert result2.paused_for_approval is False
        assert result2.completed is True
        assert mock_llm_empty.call_count == 2


@pytest.mark.asyncio
async def test_fast_router_conjunction_and_distinct_actions(setup_env):
    """Verify route_command_chain splits phrases using 'and' between distinct actions."""
    db_path = setup_env["db_file"]
    chain = await route_command_chain("start trading backend and start trading frontend", db_path=db_path)
    assert chain is not None
    assert len(chain) == 2
    assert chain[0].tool_name == "start_named_service"
    assert chain[0].args.get("target") == "trading"
    assert chain[0].args.get("component") == "backend"
    assert chain[1].tool_name == "start_named_service"
    assert chain[1].args.get("target") == "trading"
    assert chain[1].args.get("component") == "frontend"


def test_inspect_project_vite_host_flag(tmp_path):
    """Verify inspect_project correctly returns the appended '--host' flag for React (Vite) projects."""
    from core.project_inspector import inspect_project

    vite_dir = tmp_path / "vite_react_app"
    vite_dir.mkdir()
    (vite_dir / "package.json").write_text(
        json.dumps({
            "name": "vite-react-app",
            "scripts": {"dev": "vite", "build": "vite build"}
        }),
        encoding="utf-8",
    )
    (vite_dir / "vite.config.ts").write_text("import { defineConfig } from 'vite';", encoding="utf-8")

    components = inspect_project(vite_dir)
    assert "root" in components
    spec = components["root"]
    assert spec.stack == "React (Vite)"
    assert spec.port == 5173
    assert "--host" in spec.cmd
    assert spec.cmd[-2:] == ["--", "--host"]


@pytest.mark.asyncio
async def test_ai_planner_truncates_parallel_tool_calls(setup_env, capsys):
    """Verify backend enforces single tool execution by truncating parallel tool calls to the first tool."""
    planner = AIPlanner()

    mock_parallel_response = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "get_system_vitals",
                                "arguments": "{}",
                            },
                        },
                        {
                            "id": "call_2",
                            "type": "function",
                            "function": {
                                "name": "capture_screenshot",
                                "arguments": "{}",
                            },
                        },
                    ],
                }
            }
        ]
    }

    mock_synthesis_response = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Vitals checked successfully.",
                }
            }
        ]
    }

    with patch.object(planner, "_call_llm", new=AsyncMock(side_effect=[mock_parallel_response, mock_synthesis_response])):
        with patch("tools.system_tools.get_system_vitals", new=AsyncMock(return_value={"formatted": "CPU 10%"})):
            result = await planner.plan_and_execute("check vitals and take screenshot")

            # Must have truncated to only the first tool call
            assert len(result.executed_steps) == 1
            assert result.executed_steps[0].tool_name == "get_system_vitals"
            assert result.final_message == "Vitals checked successfully."

            # Check printed warning
            captured = capsys.readouterr()
            assert "Warning: LLM attempted parallel execution. Truncating to first tool: get_system_vitals" in captured.out

            # Check system prompt contains the sequential multi-action instruction
            system_msg = result.session_messages[0]
            assert system_msg["role"] == "system"
            assert "emit all required tool calls in order, or emit the next required tool call" in system_msg["content"]


@pytest.mark.asyncio
async def test_compound_command_bypasses_terminal_short_circuit(setup_env):
    """Verify compound command does not prematurely exit on TERMINAL_TOOLS, queuing next action."""
    planner = AIPlanner()

    mock_step1_response = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_service",
                            "type": "function",
                            "function": {
                                "name": "start_named_service",
                                "arguments": json.dumps({"name": "trading_agent"}),
                            },
                        }
                    ],
                }
            }
        ]
    }

    mock_step2_response = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_tunnel",
                            "type": "function",
                            "function": {
                                "name": "expose_port_tunnel",
                                "arguments": json.dumps({"port": 8000}),
                            },
                        }
                    ],
                }
            }
        ]
    }

    # 1. Initial plan_and_execute pauses on start_named_service (Tier 2)
    with patch.object(planner, "_call_llm", new=AsyncMock(side_effect=[mock_step1_response, mock_step2_response])):
        res1 = await planner.plan_and_execute("Start the trading agent and expose port 8000")
        assert res1.paused_for_approval is True
        assert res1.paused_tool_call is not None
        assert res1.paused_tool_call.tool_name == "start_named_service"
        assert res1.paused_tool_call.tier == SecurityTier.TIER_2_CONFIRM

        # 2. Approve start_named_service and resume
        service_output = "🚀 Service 'trading_agent' started on port 8000 (PID: 1234)"
        res2 = await planner.resume_after_approval(res1, service_output)

        # 3. Must NOT exit prematurely; must pause for Tier 2 approval on expose_port_tunnel
        assert res2.completed is False
        assert res2.paused_for_approval is True
        assert res2.paused_tool_call is not None
        assert res2.paused_tool_call.tool_name == "expose_port_tunnel"
        assert res2.paused_tool_call.tier == SecurityTier.TIER_2_CONFIRM
        assert res2.intermediate_message == service_output


@pytest.mark.asyncio
async def test_compound_command_queued_parallel_tools(setup_env):
    """Verify that if LLM emits parallel tools for compound requests, the second is queued and resumed."""
    planner = AIPlanner()

    mock_parallel_response = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_service",
                            "type": "function",
                            "function": {
                                "name": "start_named_service",
                                "arguments": json.dumps({"name": "trading_agent"}),
                            },
                        },
                        {
                            "id": "call_tunnel",
                            "type": "function",
                            "function": {
                                "name": "expose_port_tunnel",
                                "arguments": json.dumps({"port": 8000}),
                            },
                        },
                    ],
                }
            }
        ]
    }

    with patch.object(planner, "_call_llm", new=AsyncMock(return_value=mock_parallel_response)):
        res1 = await planner.plan_and_execute("Start the trading agent and expose port 8000")
        assert res1.paused_for_approval is True
        assert res1.paused_tool_call.tool_name == "start_named_service"
        assert len(planner.pending_tool_queue) == 1
        assert planner.pending_tool_queue[0].tool_name == "expose_port_tunnel"

        service_output = "🚀 Service 'trading_agent' started on port 8000"
        res2 = await planner.resume_after_approval(res1, service_output)

        assert res2.completed is False
        assert res2.paused_for_approval is True
        assert res2.paused_tool_call.tool_name == "expose_port_tunnel"
        assert res2.intermediate_message == service_output


@pytest.mark.asyncio
async def test_chained_tier2_approval_in_gateway(setup_env):
    """Verify that when resume_after_approval returns intermediate_message and pauses for chained approval,
    the gateway outputs the intermediate message and dispatches the second confirmation prompt."""
    from aiogram.types import CallbackQuery
    from bot.telegram_gateway import (
        PENDING_APPROVALS,
        PENDING_PLANNER_SESSIONS,
        handle_approve_callback,
    )
    from core.ai_planner import AIPlanner, PlannerResult
    from core.fast_router import ToolCall
    from core.permissions import SecurityTier
    from core.config import get_settings

    owner_id = get_settings().OWNER_TELEGRAM_ID
    paused_tc1 = ToolCall(
        tool_name="start_named_service",
        args={"target": "trading_agent"},
        tier=SecurityTier.TIER_2_CONFIRM,
    )
    paused_tc2 = ToolCall(
        tool_name="expose_port_tunnel",
        args={"port": 8000},
        tier=SecurityTier.TIER_2_CONFIRM,
    )

    approval_id1 = "appr_step1"
    PENDING_APPROVALS[approval_id1] = paused_tc1

    planner = AIPlanner()
    paused_result1 = PlannerResult(
        completed=False,
        paused_for_approval=True,
        paused_tool_call=paused_tc1,
        pending_tool_call=paused_tc1,
        paused_call_id="call_step1",
        tier=SecurityTier.TIER_2_CONFIRM,
        session_messages=[
            {"role": "user", "content": "Start the trading agent and expose port 8000"},
        ],
        step_count=1,
    )
    PENDING_PLANNER_SESSIONS[owner_id] = (planner, paused_result1)

    callback = MagicMock(spec=CallbackQuery)
    callback.data = f"approve:{approval_id1}"
    callback.from_user = MagicMock(id=owner_id)
    callback.message = MagicMock()
    callback.message.chat = MagicMock(id=owner_id)
    callback.message.edit_text = AsyncMock()
    callback.message.answer = AsyncMock()
    callback.answer = AsyncMock()

    mock_bot = MagicMock()
    mock_bot.send_message = AsyncMock()

    service_msg = "🚀 Service 'trading_agent' started on port 8000 (PID: 1234)"
    mock_resumed_result = PlannerResult(
        completed=False,
        paused_for_approval=True,
        paused_tool_call=paused_tc2,
        pending_tool_call=paused_tc2,
        paused_call_id="call_step2",
        tier=SecurityTier.TIER_2_CONFIRM,
        intermediate_message=service_msg,
        session_messages=paused_result1.session_messages,
        step_count=2,
    )

    with patch("bot.telegram_gateway.execute_tool_locally", new=AsyncMock(return_value=service_msg)) as mock_exec_local, \
         patch.object(planner, "resume_after_approval", new=AsyncMock(return_value=mock_resumed_result)):
        await handle_approve_callback(callback, mock_bot)

        # 1. Local tool execution occurred for step 1
        mock_exec_local.assert_called_once_with("start_named_service", {"target": "trading_agent"})

        # 2. Intermediate message was sent to chat
        assert callback.message.answer.call_count >= 2
        intermediate_call_args = callback.message.answer.call_args_list[0]
        assert service_msg in intermediate_call_args[0][0]

        # 3. Second confirmation prompt was dispatched
        prompt_call_args = callback.message.answer.call_args_list[1]
        assert "expose_port_tunnel" in prompt_call_args[0][0]
        assert "Confirmation Required for AI Plan (Tier 2)" in prompt_call_args[0][0]
        assert prompt_call_args[1].get("reply_markup") is not None

        # 4. PENDING_PLANNER_SESSIONS and PENDING_APPROVALS are updated for the second action
        assert owner_id in PENDING_PLANNER_SESSIONS
        assert PENDING_PLANNER_SESSIONS[owner_id][1].paused_tool_call.tool_name == "expose_port_tunnel"


# =====================================================================
# 8. Deterministic Gateway Command Queue & Verb-Aware Splitting
# =====================================================================


def test_split_compound_command_preserves_project_names():
    """Verify split_compound_command splits compound actions but preserves project names like sweetandcrust."""
    from bot.telegram_gateway import split_compound_command

    # 1. Compound action splitting
    parts1 = split_compound_command("start the trading agent and expose port 8000")
    assert parts1 == ["start the trading agent", "expose port 8000"]

    # 2. Project name with embedded 'and' is preserved
    parts2 = split_compound_command("run the project sweetandcrust")
    assert parts2 == ["run the project sweetandcrust"]

    # 3. Different conjunctions and verbs
    parts3 = split_compound_command("start fastapi_demo and also expose 8000")
    assert parts3 == ["start fastapi_demo", "expose 8000"]

    parts4 = split_compound_command("take a screenshot and then status")
    assert parts4 == ["take a screenshot", "status"]


@pytest.mark.asyncio
async def test_fast_router_regex_expansion(setup_env):
    """Verify expanded regex matchers in fast_router for multi-word services and optional 'port'."""
    db_path = setup_env["db_file"]

    # 1. Multi-word service with conversational filler
    tc1 = await route_command("start the trading agent", db_path=db_path)
    assert tc1 is not None
    assert tc1.tool_name == "start_named_service"
    assert tc1.args["service_name"] == "trading agent"
    assert tc1.tier == SecurityTier.TIER_2_CONFIRM

    # 2. Expose port with optional 'port'
    tc2 = await route_command("expose port 8000", db_path=db_path)
    assert tc2 is not None
    assert tc2.tool_name == "expose_port_tunnel"
    assert tc2.args["port"] == 8000
    assert tc2.tier == SecurityTier.TIER_2_CONFIRM

    # 3. Direct route_command on compound string returns None (ensuring gateway handles split)
    assert await route_command("start the trading agent and expose port 8000", db_path=db_path) is None


@pytest.mark.asyncio
async def test_gateway_command_queue_chain_execution(setup_env):
    """Verify deterministic command queue pops and executes chained actions via inline approval."""
    from aiogram.types import CallbackQuery, Message
    from bot.telegram_gateway import (
        PENDING_APPROVALS,
        PENDING_COMMAND_QUEUE,
        PENDING_PLANNER_SESSIONS,
        handle_approve_callback,
        handle_cancel_callback,
        handle_text_message,
    )
    from core.config import get_settings

    owner_id = get_settings().OWNER_TELEGRAM_ID
    PENDING_APPROVALS.clear()
    PENDING_COMMAND_QUEUE.clear()
    PENDING_PLANNER_SESSIONS.clear()

    mock_bot = MagicMock()
    mock_bot.send_message = AsyncMock()

    mock_msg = MagicMock(spec=Message)
    mock_msg.text = "start the trading agent and expose port 8000"
    mock_msg.from_user = MagicMock(id=owner_id)
    mock_msg.chat = MagicMock(id=owner_id)
    mock_msg.answer = AsyncMock()

    # 1. Message arrives: splits and executes first command, queues the second
    await handle_text_message(mock_msg, mock_bot)

    # First command is 'start the trading agent' (Tier 2 -> inline keyboard confirmation)
    assert mock_msg.answer.call_count == 1
    prompt1 = mock_msg.answer.call_args[0][0]
    assert "start_named_service" in prompt1
    assert "Confirmation Required (Tier 2)" in prompt1
    assert len(PENDING_APPROVALS) == 1
    approval_id1 = list(PENDING_APPROVALS.keys())[0]

    # Queue must hold the remaining command
    assert PENDING_COMMAND_QUEUE.get(owner_id) == ["expose port 8000"]

    # 2. User approves the first action
    cb1 = MagicMock(spec=CallbackQuery)
    cb1.data = f"approve:{approval_id1}"
    cb1.from_user = MagicMock(id=owner_id)
    cb1.message = MagicMock(spec=Message)
    cb1.message.chat = MagicMock(id=owner_id)
    cb1.message.edit_text = AsyncMock()
    cb1.message.answer = AsyncMock()
    cb1.answer = AsyncMock()

    with patch("tools.dev_services.start_named_service", new=AsyncMock(return_value={"status": "success", "message": "🚀 Started Service: trading_agent_backend"})):
        await handle_approve_callback(cb1, mock_bot)

        # Output message sent for first tool
        mock_bot.send_message.assert_awaited()
        assert "Started Service: trading_agent_backend" in mock_bot.send_message.call_args[0][1]

        # Second action 'expose port 8000' is automatically popped and executed
        assert PENDING_COMMAND_QUEUE.get(owner_id, []) == []
        assert cb1.message.answer.call_count == 1
        prompt2 = cb1.message.answer.call_args[0][0]
        assert "expose_port_tunnel" in prompt2
        assert "Confirmation Required (Tier 2)" in prompt2

    # 3. Test Queue Cleanup on Cancel:
    # If user cancels the second action, queue is clean
    assert len(PENDING_APPROVALS) == 1
    approval_id2 = list(PENDING_APPROVALS.keys())[0]

    cb_cancel = MagicMock(spec=CallbackQuery)
    cb_cancel.data = f"cancel:{approval_id2}"
    cb_cancel.from_user = MagicMock(id=owner_id)
    cb_cancel.message = MagicMock(spec=Message)
    cb_cancel.message.edit_text = AsyncMock()
    cb_cancel.answer = AsyncMock()

    await handle_cancel_callback(cb_cancel)
    assert len(PENDING_APPROVALS) == 0
    assert owner_id not in PENDING_COMMAND_QUEUE


# =====================================================================
# 11. Anti-Theft Surveillance, Webcam Capture & Multi-Window Screenshots
# =====================================================================


@pytest.mark.asyncio
async def test_fast_router_surveillance_and_antitheft_commands(setup_env):
    """Verify fast_router routes '📷 Webcam', '📍 Locate', '🔒 Lock PC', and 'screenshot windows 4' deterministically with 0 tokens."""
    db_file = setup_env["db_file"]

    # 1. Webcam Snapshot
    tc_webcam = await route_command("📷 Webcam", db_path=db_file)
    assert tc_webcam is not None
    assert tc_webcam.tool_name == "capture_webcam_photo"
    assert tc_webcam.tier == SecurityTier.TIER_1_AUTO

    tc_webcam_plain = await route_command("webcam", db_path=db_file)
    assert tc_webcam_plain is not None
    assert tc_webcam_plain.tool_name == "capture_webcam_photo"
    assert tc_webcam_plain.tier == SecurityTier.TIER_1_AUTO

    tc_intruder = await route_command("intruder photo", db_path=db_file)
    assert tc_intruder is not None
    assert tc_intruder.tool_name == "capture_webcam_photo"

    tc_snap = await route_command("snap photo", db_path=db_file)
    assert tc_snap is not None
    assert tc_snap.tool_name == "capture_webcam_photo"

    # 2. Location Telemetry
    tc_locate = await route_command("📍 Locate", db_path=db_file)
    assert tc_locate is not None
    assert tc_locate.tool_name == "get_location_telemetry"
    assert tc_locate.tier == SecurityTier.TIER_1_AUTO

    tc_locate_plain = await route_command("locate", db_path=db_file)
    assert tc_locate_plain is not None
    assert tc_locate_plain.tool_name == "get_location_telemetry"

    tc_where = await route_command("where is my pc", db_path=db_file)
    assert tc_where is not None
    assert tc_where.tool_name == "get_location_telemetry"

    tc_track = await route_command("track pc", db_path=db_file)
    assert tc_track is not None
    assert tc_track.tool_name == "get_location_telemetry"

    # 3. Lock Workstation
    tc_lock = await route_command("🔒 Lock PC", db_path=db_file)
    assert tc_lock is not None
    assert tc_lock.tool_name == "lock_workstation"
    assert tc_lock.tier == SecurityTier.TIER_1_AUTO

    tc_lock_plain = await route_command("lock pc", db_path=db_file)
    assert tc_lock_plain is not None
    assert tc_lock_plain.tool_name == "lock_workstation"

    tc_lock_screen = await route_command("lock screen", db_path=db_file)
    assert tc_lock_screen is not None
    assert tc_lock_screen.tool_name == "lock_workstation"

    tc_lock_laptop = await route_command("lock laptop", db_path=db_file)
    assert tc_lock_laptop is not None
    assert tc_lock_laptop.tool_name == "lock_workstation"

    # 4. Multi-Screenshots (Windows and Apps)
    tc_multi = await route_command("screenshot windows 4", db_path=db_file)
    assert tc_multi is not None
    assert tc_multi.tool_name == "capture_multi_screenshots"
    assert tc_multi.args == {"mode": "windows", "count": 4}
    assert tc_multi.tier == SecurityTier.TIER_1_AUTO

    tc_multi_windows = await route_command("screenshot windows 3", db_path=db_file)
    assert tc_multi_windows is not None
    assert tc_multi_windows.tool_name == "capture_multi_screenshots"
    assert tc_multi_windows.args == {"mode": "windows", "count": 3}

    tc_multi_all = await route_command("screenshot all windows", db_path=db_file)
    assert tc_multi_all is not None
    assert tc_multi_all.tool_name == "capture_multi_screenshots"
    assert tc_multi_all.args["mode"] == "windows"
    assert tc_multi_all.args["count"] == 6

    # Singular and modifier natural phrasing
    tc_win_singular = await route_command("Screenshot window 3", db_path=db_file)
    assert tc_win_singular is not None
    assert tc_win_singular.tool_name == "capture_multi_screenshots"
    assert tc_win_singular.args == {"mode": "windows", "count": 3}

    tc_diff_win = await route_command("Different window screenshot", db_path=db_file)
    assert tc_diff_win is not None
    assert tc_diff_win.tool_name == "capture_multi_screenshots"
    assert tc_diff_win.args == {"mode": "windows", "count": 4}

    tc_multi_num_first = await route_command("screenshot 2 windows", db_path=db_file)
    assert tc_multi_num_first is not None
    assert tc_multi_num_first.tool_name == "capture_multi_screenshots"
    assert tc_multi_num_first.args == {"mode": "windows", "count": 2}

    tc_multiple_windows = await route_command("multiple window screenshots", db_path=db_file)
    assert tc_multiple_windows is not None
    assert tc_multiple_windows.tool_name == "capture_multi_screenshots"
    assert tc_multiple_windows.args == {"mode": "windows", "count": 4}

    tc_multi_apps = await route_command("screenshot apps 3", db_path=db_file)
    assert tc_multi_apps is not None
    assert tc_multi_apps.tool_name == "capture_multi_screenshots"
    assert tc_multi_apps.args == {"mode": "windows", "count": 3}


@pytest.mark.asyncio
async def test_surveillance_tools_unit(tmp_path, monkeypatch):
    """Unit test surveillance tool implementations."""
    from tools import surveillance

    # Override UNDO_DIR to test tmp_path
    monkeypatch.setattr(get_settings(), "UNDO_DIR", tmp_path / "undo_storage")

    # 1. capture_webcam_photo unit test with mock cv2
    mock_cv2 = MagicMock()
    mock_cap = MagicMock()
    mock_cap.isOpened.return_value = True
    mock_cap.read.return_value = (True, "mock_frame_data")
    mock_cv2.VideoCapture.return_value = mock_cap
    mock_cv2.imwrite = MagicMock(return_value=True)

    with patch.dict("sys.modules", {"cv2": mock_cv2}):
        res = surveillance.capture_webcam_photo(camera_index=0)
        assert res["status"] == "success"
        assert "image_path" in res
        assert "webcam_snap.jpg" in res["image_path"]
        assert mock_cap.read.call_count == 13  # 12 warm-up + 1 final
        mock_cap.release.assert_called_once()
        mock_cv2.imwrite.assert_called_once()

    # 2. capture_webcam_photo failure when camera cannot be opened
    mock_cap_fail = MagicMock()
    mock_cap_fail.isOpened.return_value = False
    mock_cv2_fail = MagicMock()
    mock_cv2_fail.VideoCapture.return_value = mock_cap_fail

    with patch.dict("sys.modules", {"cv2": mock_cv2_fail}):
        res_fail = surveillance.capture_webcam_photo(camera_index=1)
        assert res_fail["status"] == "error"
        assert "Could not access webcam" in res_fail["message"]

    # 3. capture_multi_screenshots bounds capping and execution
    fake_registry = [
        {"id": i, "hwnd": 1000 + i, "app": f"app_{i}", "exe": f"app_{i}.exe", "title": f"App {i}", "is_minimized": False}
        for i in range(1, 9)
    ]
    with patch.object(surveillance, "WINDOW_REGISTRY", fake_registry), \
         patch("tools.surveillance.refresh_window_registry"), \
         patch("tools.surveillance.capture_single_hwnd", side_effect=lambda entry: f"/tmp/win_{entry['id']}.png") as mock_cap_win:

        # Count 1 capped to 2
        res_win = surveillance.capture_multi_screenshots(mode="windows", count=1)
        assert res_win["status"] == "success"
        assert res_win["mode"] == "windows"
        assert len(res_win["image_paths"]) == 2
        assert mock_cap_win.call_count == 2

        # Count 10 capped to 6
        mock_cap_win.reset_mock()
        res_win_max = surveillance.capture_multi_screenshots(mode="windows", count=10)
        assert res_win_max["status"] == "success"
        assert res_win_max["mode"] == "windows"
        assert len(res_win_max["image_paths"]) == 6
        assert mock_cap_win.call_count == 6

    # 3b. capture_multi_screenshots fallback to desktop when no windows detected
    with patch.object(surveillance, "WINDOW_REGISTRY", []), \
         patch("tools.surveillance.refresh_window_registry"), \
         patch("mss.mss") as mock_mss:
        mock_sct = MagicMock()
        mock_mss.return_value.__enter__.return_value = mock_sct
        res_empty = surveillance.capture_multi_screenshots(mode="windows", count=3)
        assert res_empty["status"] == "success"
        assert len(res_empty["image_paths"]) == 1
        assert "Desktop Screenshot" in res_empty["message"]

    # 4. get_location_telemetry parsing
    dummy_ip_json = json.dumps({
        "status": "success",
        "query": "203.0.113.195",
        "isp": "Acme Fiber",
        "city": "Bengaluru",
        "regionName": "Karnataka",
        "country": "India",
        "lat": 12.9716,
        "lon": 77.5946,
    }).encode("utf-8")

    dummy_netsh_out = (
        "SSID 1 : Office_5G\n"
        "    Network type            : Infrastructure\n"
        "    Authentication          : WPA2-Personal\n"
        "    Encryption              : CCMP\n"
        "    BSSID 1                 : aa:bb:cc:dd:ee:ff\n"
        "         Signal             : 92%\n"
    )

    mock_resp = MagicMock()
    mock_resp.read.return_value = dummy_ip_json
    mock_resp.__enter__.return_value = mock_resp

    mock_proc = MagicMock()
    mock_proc.stdout = dummy_netsh_out

    with patch("urllib.request.urlopen", return_value=mock_resp), \
         patch("subprocess.run", return_value=mock_proc):
        telem = surveillance.get_location_telemetry()
        assert telem["status"] == "success"
        assert telem["public_ip"] == "203.0.113.195"
        assert telem["isp"] == "Acme Fiber"
        assert "Bengaluru" in telem["location"]
        assert len(telem["wifi_networks"]) == 1
        assert telem["wifi_networks"][0]["ssid"] == "Office_5G"
        assert telem["wifi_networks"][0]["bssid"] == "aa:bb:cc:dd:ee:ff"
        assert telem["wifi_networks"][0]["signal"] == "92%"
        assert "📍 *Location & Network Telemetry*" in telem["message"]

    # 5. lock_workstation execution (safe mock)
    with patch("ctypes.windll.user32.LockWorkStation") as mock_lock, \
         patch("ctypes.windll.user32.OpenClipboard", return_value=1), \
         patch("ctypes.windll.user32.EmptyClipboard"), \
         patch("ctypes.windll.user32.CloseClipboard"):
        lock_res = surveillance.lock_workstation()
        assert lock_res["status"] == "success"
        assert "Windows workstation locked" in lock_res["message"]
        mock_lock.assert_called_once()


@pytest.mark.asyncio
async def test_send_startup_beacon():
    """Verify send_startup_beacon dispatches location telemetry to owner."""
    from aiogram import Bot
    from bot.telegram_gateway import send_startup_beacon

    mock_bot = AsyncMock(spec=Bot)
    owner_id = 99887766

    settings = get_settings()
    settings.OWNER_TELEGRAM_ID = owner_id
    settings.ENABLE_STARTUP_BEACON = True

    dummy_telem = {
        "status": "success",
        "formatted": "📍 *Mock Telemetry*\n🌐 *Public IP:* `1.2.3.4`",
    }

    with patch("tools.surveillance.get_location_telemetry", return_value=dummy_telem):
        await send_startup_beacon(mock_bot)
        mock_bot.send_message.assert_awaited_once()
        args = mock_bot.send_message.call_args[0]
        assert args[0] == owner_id
        assert "🚨 *PocketPC Agent Online*" in args[1]
        assert "1.2.3.4" in args[1]


@pytest.mark.asyncio
async def test_deliver_planner_visual_assets(tmp_path):
    """Verify deliver_planner_visual_assets uploads photos and albums to Telegram."""
    from aiogram import Bot
    from bot.telegram_gateway import deliver_planner_visual_assets
    from tools import surveillance, system_tools

    mock_bot = AsyncMock(spec=Bot)
    chat_id = 12345678

    # 1. Test single screenshot upload
    test_shot = tmp_path / "test_shot.png"
    test_shot.write_bytes(b"dummy_png_bytes")
    system_tools.LAST_SCREENSHOT_PATH = test_shot

    planner_res_single = PlannerResult(
        completed=True,
        final_message=f"Screenshot saved successfully at: {test_shot}",
        executed_steps=[ToolCall(tool_name="capture_screenshot", tier=SecurityTier.TIER_1_AUTO)],
    )

    await deliver_planner_visual_assets(planner_res_single, mock_bot, chat_id)
    mock_bot.send_photo.assert_awaited_once()
    assert mock_bot.send_photo.call_args[0][0] == chat_id

    # 2. Test multi-screenshot album upload
    mock_bot.reset_mock()
    win1 = tmp_path / "win1.png"
    win2 = tmp_path / "win2.png"
    win1.write_bytes(b"img1")
    win2.write_bytes(b"img2")
    surveillance.LAST_MULTI_SCREENSHOT_PATHS = [str(win1), str(win2)]

    planner_res_multi = PlannerResult(
        completed=True,
        final_message="I captured the windows.",
        executed_steps=[ToolCall(tool_name="capture_multi_screenshots", args={"mode": "windows", "count": 2}, tier=SecurityTier.TIER_1_AUTO)],
    )

    await deliver_planner_visual_assets(planner_res_multi, mock_bot, chat_id)
    mock_bot.send_media_group.assert_awaited_once()
    assert mock_bot.send_media_group.call_args[0][0] == chat_id


@pytest.mark.asyncio
async def test_multi_screenshot_routing_natural_phrasing():
    """Verify route_command matches singular/plural and natural phrases."""
    tc1 = await route_command("Different window screenshot")
    assert tc1 is not None
    assert tc1.name == "capture_multi_screenshots"
    assert tc1.arguments == {"mode": "windows", "count": 4}
    assert tc1 == ToolCall(name="capture_multi_screenshots", arguments={"mode": "windows", "count": 4})

    tc2 = await route_command("Screenshot window 3")
    assert tc2 is not None
    assert tc2.name == "capture_multi_screenshots"
    assert tc2.arguments == {"mode": "windows", "count": 3}
    assert tc2 == ToolCall(name="capture_multi_screenshots", arguments={"mode": "windows", "count": 3})


@pytest.mark.asyncio
async def test_send_tool_response_or_media_string_screenshot():
    """Verify send_tool_response_or_media calls answer_photo when given a flattened screenshot string."""
    from aiogram.types import Message
    from bot.telegram_gateway import send_tool_response_or_media

    mock_msg = MagicMock(spec=Message)
    mock_msg.answer_photo = AsyncMock()
    mock_msg.answer_media_group = AsyncMock()
    mock_msg.answer = AsyncMock()
    raw_str = r"Screenshot saved successfully at: C:\Temp\test.png"

    with patch("os.path.exists", return_value=True):
        await send_tool_response_or_media(mock_msg, raw_str)
        mock_msg.answer_photo.assert_awaited_once()
        call_args = mock_msg.answer_photo.call_args
        assert call_args[1].get("caption") == "📸 Screenshot captured"


@pytest.mark.asyncio
async def test_send_tool_response_or_media_dict_album_and_single(tmp_path):
    """Verify send_tool_response_or_media handles dict payloads for albums and single photos."""
    from aiogram.types import Message
    from bot.telegram_gateway import send_tool_response_or_media

    mock_msg = MagicMock(spec=Message)
    mock_msg.answer_photo = AsyncMock()
    mock_msg.answer_media_group = AsyncMock()
    mock_msg.answer = AsyncMock()

    # 1. Multi-image album dict
    p1 = tmp_path / "img1.png"
    p2 = tmp_path / "img2.png"
    p1.write_bytes(b"1")
    p2.write_bytes(b"2")

    album_dict = {
        "status": "success",
        "image_paths": [str(p1), str(p2)],
        "message": "📸 Captured 2 windows screenshots.",
    }
    await send_tool_response_or_media(mock_msg, album_dict)
    mock_msg.answer_media_group.assert_awaited_once()

    # 2. Single image dict
    mock_msg.reset_mock()
    single_dict = {
        "status": "success",
        "image_path": str(p1),
        "message": "📷 Webcam snapshot captured.",
    }
    await send_tool_response_or_media(mock_msg, single_dict)
    mock_msg.answer_photo.assert_awaited_once()
    assert mock_msg.answer_photo.call_args[1].get("caption") == "📷 Webcam snapshot captured."


@pytest.mark.asyncio
async def test_window_registry_filters_nahimic_and_cloaked():
    """Verify that Nahimic Companion, background denylist apps, and cloaked windows are excluded."""
    from tools import surveillance

    mock_windows = [
        {"hwnd": 1001, "title": "Nahimic Companion", "exe": "NahimicService.exe", "visible": True, "cloaked": 0},
        {"hwnd": 1002, "title": "Settings", "exe": "SystemSettings.exe", "visible": True, "cloaked": 0},
        {"hwnd": 1003, "title": "Hidden Window", "exe": "app.exe", "visible": True, "cloaked": 1},
        {"hwnd": 1004, "title": "Invisible Tool", "exe": "app.exe", "visible": False, "cloaked": 0},
        {"hwnd": 1005, "title": "Google Chrome", "exe": "chrome.exe", "visible": True, "cloaked": 0},
        {"hwnd": 1006, "title": "Visual Studio Code", "exe": "Code.exe", "visible": True, "cloaked": 0},
    ]

    with patch.object(surveillance, "sys") as mock_sys:
        mock_sys.platform = "win32"
        mock_user32 = MagicMock()
        mock_dwmapi = MagicMock()
        dummy_windll = MagicMock()
        dummy_windll.user32 = mock_user32
        dummy_windll.dwmapi = mock_dwmapi
        dummy_windll.kernel32 = MagicMock()

        with patch.object(surveillance.ctypes, "windll", dummy_windll, create=True):
            def fake_enum_windows(hdesk_or_cb, cb_or_lparam, lparam=0):
                cb = cb_or_lparam if callable(cb_or_lparam) else hdesk_or_cb
                for w in mock_windows:
                    mock_user32.IsWindowVisible.return_value = w["visible"]
                    mock_user32.GetWindowTextLengthW.return_value = len(w["title"])

                    def make_get_text(t):
                        def _get_text(hwnd, buf, max_len):
                            buf.value = t
                            return len(t)
                        return _get_text
                    mock_user32.GetWindowTextW.side_effect = make_get_text(w["title"])

                    def make_cloaked(c):
                        def _cloaked(h, attr, ptr, sz):
                            try:
                                ptr._obj.value = c
                            except Exception:
                                pass
                            return 0
                        return _cloaked
                    mock_dwmapi.DwmGetWindowAttribute.side_effect = make_cloaked(w["cloaked"])

                    with patch("psutil.Process") as mock_proc:
                        mock_proc.return_value.name.return_value = w["exe"]
                        cb(w["hwnd"], 0)
                return 1

            mock_user32.OpenInputDesktop.return_value = 123
            mock_user32.EnumDesktopWindows.side_effect = fake_enum_windows
            mock_user32.GetWindowLongW.return_value = 0
            mock_user32.GetWindowLongPtrW.return_value = 0

            reg = surveillance.refresh_window_registry()
            apps = [entry["app"] for entry in reg]
            titles = [entry["title"] for entry in reg]

            assert "chrome" in apps
            assert "code" in apps
            assert not any("nahimic" in a.lower() for a in apps)
            assert not any("settings" in a.lower() for a in apps)
            assert not any("hidden" in t.lower() for t in titles)


@pytest.mark.asyncio
async def test_fast_router_targeted_window_screenshot():
    """Verify targeted window queries route to capture_window_by_query and 'all windows' routes to capture_multi_screenshots."""
    from core.fast_router import route_command, ToolCall

    tc_chrome = await route_command("give me the screenshot of chrome")
    assert tc_chrome is not None
    assert tc_chrome.name == "capture_window_by_query"
    assert tc_chrome.arguments == {"query": "chrome"}

    tc_vscode = await route_command("screenshot vscode")
    assert tc_vscode is not None
    assert tc_vscode.name == "capture_window_by_query"
    assert tc_vscode.arguments == {"query": "vscode"}

    tc_all = await route_command("show me all windows")
    assert tc_all is not None
    assert tc_all.name == "capture_multi_screenshots"
    assert tc_all.arguments == {"mode": "windows", "count": 6}

    tc_all_win = await route_command("screenshot all windows")
    assert tc_all_win is not None
    assert tc_all_win.name == "capture_multi_screenshots"
    assert tc_all_win.arguments == {"mode": "windows", "count": 6}


@pytest.mark.asyncio
async def test_capture_window_by_query_missing_app():
    """Verify querying an unopened app returns a clean list of WINDOW_REGISTRY without activating anything."""
    from tools import surveillance

    surveillance.WINDOW_REGISTRY = [
        {"id": 1, "hwnd": 101, "app": "chrome", "exe": "chrome.exe", "title": "Google Chrome", "is_minimized": False},
        {"id": 2, "hwnd": 102, "app": "code", "exe": "Code.exe", "title": "Visual Studio Code", "is_minimized": False},
    ]

    with patch("tools.surveillance.capture_single_hwnd") as mock_cap, \
         patch("tools.surveillance.refresh_window_registry"):
        res = surveillance.capture_window_by_query("spotify")
        assert res["status"] == "error"
        assert "No open window matching `spotify` found in active registry" in res["message"]
        assert "chrome" in res["message"]
        assert "code" in res["message"]
        mock_cap.assert_not_called()
















