"""Tests for Phase 4: Secret Scrubber, Bounded AI Planner, and Saved Skills."""

import json
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from core import db
from core.ai_planner import AIPlanner, MAX_PLANNER_STEPS, PlannerResult
from core.config import get_settings
from core.fast_router import ToolCall
from core.permissions import SecurityTier
from core.scrubber import contains_secrets, scrub_secrets, REDACTED_TOKEN
from core.skills import (
    Skill,
    delete_skill,
    get_skill,
    list_skills,
    save_skill,
    steps_to_tool_calls,
)
from bot.telegram_gateway import handle_text_message


@pytest.fixture
async def setup_env(tmp_path):
    """Set up test database and fixtures."""
    db_file = tmp_path / "test_phase4.db"
    await db.init_db(db_file)
    yield {
        "db_file": db_file,
        "tmp_path": tmp_path,
    }


# =====================================================================
# 1. Pre-Flight Secret Scrubber Tests
# =====================================================================


def test_scrub_api_keys():
    """Verify scrubber redacts OpenAI, Anthropic, Groq, and GitHub keys."""
    # OpenAI keys
    assert scrub_secrets("sk-proj-1234567890abcdef1234567890abcdef") == REDACTED_TOKEN
    assert scrub_secrets("sk-admin-1234567890abcdef1234567890abcdef") == REDACTED_TOKEN
    assert scrub_secrets("sk-1234567890abcdef1234567890abcdef12345678") == REDACTED_TOKEN

    # Anthropic key
    assert scrub_secrets("sk-ant-api03-abcdef1234567890abcdef1234567890") == REDACTED_TOKEN

    # Groq key
    assert scrub_secrets("gsk_1234567890abcdef1234567890abcdef") == REDACTED_TOKEN

    # GitHub tokens
    assert scrub_secrets("ghp_1234567890abcdef1234567890abcdef1234") == REDACTED_TOKEN
    assert scrub_secrets("github_pat_11AAAAAAA0123456789_abcdefghijklmnopqrstuvwxyz") == REDACTED_TOKEN


def test_scrub_bearer_tokens():
    """Verify Authorization Bearer tokens are redacted."""
    raw = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    scrubbed = scrub_secrets(raw)
    assert f"Bearer {REDACTED_TOKEN}" in scrubbed
    assert "eyJhbGci" not in scrubbed


def test_scrub_env_key_value_pairs():
    """Verify .env sensitive assignments are redacted."""
    raw_env = (
        "TELEGRAM_BOT_TOKEN=123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11\n"
        "DB_PASSWORD=my_super_secret_pw!\n"
        "DATABASE_URL=postgres://user:pass@localhost:5432/db\n"
        "API_SECRET='super-secret-key-999'\n"
        "DEBUG=True\n"
    )
    scrubbed = scrub_secrets(raw_env)
    assert f"TELEGRAM_BOT_TOKEN={REDACTED_TOKEN}" in scrubbed
    assert f"DB_PASSWORD={REDACTED_TOKEN}" in scrubbed
    assert f"API_SECRET={REDACTED_TOKEN}" in scrubbed
    # Non-secret config should remain untouched
    assert "DEBUG=True" in scrubbed


def test_scrub_ipv4_ports_and_credit_cards():
    """Verify IP:port endpoints and 16-digit credit cards are redacted."""
    raw_ip = "Connect to 192.168.1.50:8080 or 10.0.0.1:443 for details."
    scrubbed_ip = scrub_secrets(raw_ip)
    assert "192.168.1.50:8080" not in scrubbed_ip
    assert REDACTED_TOKEN in scrubbed_ip

    raw_cc = "Payment with 4111-2222-3333-4444 or 5500 0000 1111 2222."
    scrubbed_cc = scrub_secrets(raw_cc)
    assert "4111-2222-3333-4444" not in scrubbed_cc
    assert "5500 0000 1111 2222" not in scrubbed_cc
    assert REDACTED_TOKEN in scrubbed_cc


def test_contains_secrets():
    """Verify contains_secrets helper accurately reports detection."""
    assert contains_secrets("Nothing sensitive here") is False
    assert contains_secrets("sk-proj-1234567890abcdef1234567890abcdef") is True


# =====================================================================
# 2. Saved Skills CRUD Tests
# =====================================================================


@pytest.mark.asyncio
async def test_skills_crud(setup_env):
    """Verify saving, retrieving, listing, and deleting multi-step skills."""
    db_path = setup_env["db_file"]

    steps = [
        {"tool_name": "find_files", "args": {"query": "resume"}},
        {"tool_name": "zip_and_prepare", "args": {"path": "sandbox_files"}},
    ]

    # Save
    skill = await save_skill(
        name="backup_resume",
        steps=steps,
        description="Find resume and zip it",
        db_path=db_path,
    )
    assert skill.name == "backup_resume"
    assert len(skill.steps) == 2

    # Get
    retrieved = await get_skill("backup_resume", db_path=db_path)
    assert retrieved is not None
    assert retrieved.name == "backup_resume"
    assert retrieved.description == "Find resume and zip it"
    assert len(retrieved.steps) == 2

    # Steps to tool calls
    calls = steps_to_tool_calls(retrieved)
    assert len(calls) == 2
    assert calls[0].tool_name == "find_files"
    assert calls[0].tier == SecurityTier.TIER_1_AUTO
    assert calls[1].tool_name == "zip_and_prepare"
    assert calls[1].tier == SecurityTier.TIER_2_CONFIRM

    # List
    all_skills = await list_skills(db_path=db_path)
    assert len(all_skills) == 1
    assert all_skills[0].name == "backup_resume"

    # Delete
    deleted = await delete_skill("backup_resume", db_path=db_path)
    assert deleted is True
    assert await get_skill("backup_resume", db_path=db_path) is None


# =====================================================================
# 3. Bounded AI Planner Tests
# =====================================================================


@pytest.mark.asyncio
async def test_ai_planner_pre_flight_scrubbing(setup_env):
    """Verify user message is scrubbed before being passed to LLM."""
    planner = AIPlanner()

    mock_llm_response = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "I have processed your request without seeing your API key.",
                }
            }
        ]
    }

    with patch.object(planner, "_call_llm", new=AsyncMock(return_value=mock_llm_response)) as mock_call:
        prompt_with_secret = "My OpenAI key is sk-proj-1234567890abcdef1234567890abcdef. Please check vitals."
        result = await planner.plan_and_execute(prompt_with_secret)

        assert result.completed is True
        assert "processed your request" in result.final_message

        # Assert that the message passed into _call_llm had the secret scrubbed
        sent_messages = mock_call.call_args[0][0]
        user_message_content = sent_messages[1]["content"]
        assert "sk-proj-" not in user_message_content
        assert REDACTED_TOKEN in user_message_content


@pytest.mark.asyncio
async def test_ai_planner_max_steps_cap(setup_env):
    """Verify execution is capped at strict maximum of 6 steps."""
    planner = AIPlanner(max_steps=MAX_PLANNER_STEPS)

    # Mock LLM to always request a Tier 1 tool call
    mock_loop_response = {
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

    with patch.object(planner, "_call_llm", new=AsyncMock(return_value=mock_loop_response)) as mock_call:
        result = await planner.plan_and_execute("Monitor my CPU continuously")

        # Must halt after 6 steps
        assert result.completed is False
        assert result.step_count == MAX_PLANNER_STEPS
        assert f"maximum of {MAX_PLANNER_STEPS} steps" in result.final_message
        assert mock_call.call_count == MAX_PLANNER_STEPS


@pytest.mark.asyncio
async def test_ai_planner_pauses_on_tier_2_and_tier_3(setup_env):
    """Verify that if LLM calls a Tier 2 or Tier 3 tool, planner pauses execution."""
    planner = AIPlanner()

    # Mock LLM requesting Tier 2 tool: safe_move
    mock_tier2_response = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_move_1",
                            "type": "function",
                            "function": {
                                "name": "safe_move",
                                "arguments": json.dumps({"src": "a.txt", "dst": "b.txt"}),
                            },
                        }
                    ],
                }
            }
        ]
    }

    with patch.object(planner, "_call_llm", new=AsyncMock(return_value=mock_tier2_response)):
        result = await planner.plan_and_execute("Move my file from a to b")

        assert result.completed is False
        assert result.paused_for_approval is True
        assert result.paused_tool_call is not None
        assert result.paused_tool_call.tool_name == "safe_move"
        assert result.paused_tool_call.tier == SecurityTier.TIER_2_CONFIRM


@pytest.mark.asyncio
async def test_ai_planner_blocks_tier_4(setup_env):
    """Verify that if LLM tries to execute a Tier 4 command, it is blocked immediately."""
    planner = AIPlanner()

    mock_tier4_response = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_evil",
                            "type": "function",
                            "function": {
                                "name": "run_shell",
                                "arguments": json.dumps({"command": "format C:"}),
                            },
                        }
                    ],
                }
            },
            {
                "message": {
                    "role": "assistant",
                    "content": "Action blocked by safety policy.",
                }
            },
        ]
    }

    # First call returns format C:, second call returns final explanation
    mock_call = AsyncMock(side_effect=[
        {"choices": [mock_tier4_response["choices"][0]]},
        {"choices": [mock_tier4_response["choices"][1]]},
    ])

    with patch.object(planner, "_call_llm", new=mock_call):
        result = await planner.plan_and_execute("Format my drive")

        # Check that error was injected to model
        tool_feedback = result.session_messages[-1]
        assert tool_feedback["role"] == "tool"
        assert "blocked by Tier 4 security policy" in tool_feedback["content"]


# =====================================================================
# 4. Telegram Gateway Skill Execution Integration
# =====================================================================


@pytest.mark.asyncio
async def test_telegram_gateway_saved_skill_execution(setup_env):
    """Verify sending a saved skill name executes its steps directly."""
    # Pre-save a skill
    await save_skill(
        name="daily_check",
        steps=[{"tool_name": "get_system_vitals", "args": {}}],
        description="Check vitals",
    )

    mock_message = MagicMock()
    mock_message.text = "daily_check"
    mock_message.from_user = MagicMock(id=get_settings().OWNER_TELEGRAM_ID)
    mock_message.chat = MagicMock(id=12345)
    mock_message.answer = AsyncMock()
    mock_bot = MagicMock()
    mock_bot.send_message = AsyncMock()

    await handle_text_message(mock_message, mock_bot)

    mock_message.answer.assert_awaited()
    assert "Executing Saved Skill" in mock_message.answer.call_args[0][0]
    # Tool executed (vitals sent via send_message)
    mock_bot.send_message.assert_awaited()
