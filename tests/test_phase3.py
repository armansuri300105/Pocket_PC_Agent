"""Tests for Phase 3: Telegram Gateway, Owner-Only Middleware, Panic Stop, and Approvals."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from aiogram.types import CallbackQuery, Message, User, Chat
from core import db
from core.config import get_settings
from core.permissions import SecurityTier
from core.fast_router import ToolCall
from bot.telegram_gateway import (
    OwnerOnlyMiddleware,
    is_system_locked,
    lock_system,
    unlock_system,
    PENDING_APPROVALS,
    PENDING_PIN_ACTIONS,
    ACTIVE_TASKS,
    handle_stop,
    handle_learn,
    handle_text_message,
    handle_approve_callback,
    handle_cancel_callback,
)
from main import ensure_sandbox_fixtures


@pytest.fixture(autouse=True)
def reset_gateway_state():
    """Reset gateway global state between test runs."""
    unlock_system()
    PENDING_APPROVALS.clear()
    PENDING_PIN_ACTIONS.clear()
    ACTIVE_TASKS.clear()
    yield
    unlock_system()
    PENDING_APPROVALS.clear()
    PENDING_PIN_ACTIONS.clear()
    ACTIVE_TASKS.clear()


@pytest.fixture
async def setup_db(tmp_path):
    """Initialize test SQLite database."""
    db_file = tmp_path / "test_gateway.db"
    await db.init_db(db_file)
    yield db_file


# =====================================================================
# 1. Owner-Only Middleware Tests
# =====================================================================


@pytest.mark.asyncio
async def test_owner_only_middleware_allows_owner():
    """Verify owner is allowed through middleware."""
    owner_id = 999888777
    middleware = OwnerOnlyMiddleware(owner_id=owner_id)

    mock_handler = AsyncMock(return_value="executed")
    mock_event = MagicMock()
    owner_user = MagicMock(spec=User, id=owner_id)

    result = await middleware(
        mock_handler,
        mock_event,
        {"event_from_user": owner_user},
    )
    assert result == "executed"
    mock_handler.assert_awaited_once_with(mock_event, {"event_from_user": owner_user})


@pytest.mark.asyncio
async def test_owner_only_middleware_silently_drops_intruder():
    """Verify non-owner messages are silently dropped without invoking handler."""
    owner_id = 999888777
    intruder_id = 111222333
    middleware = OwnerOnlyMiddleware(owner_id=owner_id)

    mock_handler = AsyncMock(return_value="executed")
    mock_event = MagicMock()
    intruder_user = MagicMock(spec=User, id=intruder_id)

    result = await middleware(
        mock_handler,
        mock_event,
        {"event_from_user": intruder_user},
    )
    assert result is None
    mock_handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_owner_only_middleware_drops_when_user_is_none():
    """Verify events without a user are dropped."""
    middleware = OwnerOnlyMiddleware(owner_id=123)
    mock_handler = AsyncMock()
    result = await middleware(mock_handler, MagicMock(), {})
    assert result is None
    mock_handler.assert_not_awaited()


# =====================================================================
# 2. Panic Command /stop and System Lock Tests
# =====================================================================


@pytest.mark.asyncio
async def test_stop_command_locks_system_and_kills_tasks(setup_db):
    """Verify /stop locks the system and cancels all background tasks."""
    # Create dummy running task
    async def dummy_work():
        await asyncio.sleep(100)

    task = asyncio.create_task(dummy_work())
    ACTIVE_TASKS.add(task)
    PENDING_APPROVALS["abc"] = ToolCall(tool_name="test", args={})

    mock_message = MagicMock(spec=Message)
    mock_message.answer = AsyncMock()

    await handle_stop(mock_message)

    assert is_system_locked() is True
    assert task.cancelled() or task.done()
    assert len(PENDING_APPROVALS) == 0
    mock_message.answer.assert_awaited_once()
    assert "EMERGENCY STOP" in mock_message.answer.call_args[0][0]


@pytest.mark.asyncio
async def test_locked_system_refuses_incoming_commands():
    """Verify commands sent while system is locked are refused."""
    lock_system()
    mock_message = MagicMock(spec=Message)
    mock_message.text = "status"
    mock_message.from_user = MagicMock(id=123)
    mock_message.answer = AsyncMock()
    mock_bot = MagicMock()

    await handle_text_message(mock_message, mock_bot)

    mock_message.answer.assert_awaited_once()
    assert "SYSTEM IS LOCKED" in mock_message.answer.call_args[0][0]


# =====================================================================
# 3. Learn Command Tests
# =====================================================================


@pytest.mark.asyncio
async def test_learn_command_saves_shortcut(setup_db):
    """Verify /learn command persists shortcuts into SQLite."""
    mock_message = MagicMock(spec=Message)
    mock_message.text = "/learn snap = screenshot"
    mock_message.answer = AsyncMock()

    await handle_learn(mock_message)

    # Check database
    mapped = await db.get_shortcut("snap")
    assert mapped == "screenshot"
    mock_message.answer.assert_awaited_once()
    assert "Shortcut Learned" in mock_message.answer.call_args[0][0]


# =====================================================================
# 4. Tier 1 Auto Execution Tests
# =====================================================================


@pytest.mark.asyncio
async def test_tier_1_auto_execute(setup_db):
    """Verify Tier 1 commands (vitals) execute immediately."""
    mock_message = MagicMock(spec=Message)
    mock_message.text = "status"
    mock_message.from_user = MagicMock(id=get_settings().OWNER_TELEGRAM_ID)
    mock_message.chat = MagicMock(id=12345)
    mock_message.answer = AsyncMock()
    mock_bot = MagicMock()
    mock_bot.send_message = AsyncMock()

    await handle_text_message(mock_message, mock_bot)

    # send_message should have been called with vitals
    mock_bot.send_message.assert_awaited_once()
    reply_text = mock_bot.send_message.call_args[0][1]
    assert "CPU:" in reply_text


# =====================================================================
# 5. Tier 2 Inline Confirmation Tests
# =====================================================================


@pytest.mark.asyncio
async def test_tier_2_confirmation_flow(setup_db):
    """Verify Tier 2 prompts with inline keyboard, and approve/cancel works."""
    mock_message = MagicMock(spec=Message)
    mock_message.text = "zip my_folder"
    mock_message.from_user = MagicMock(id=get_settings().OWNER_TELEGRAM_ID)
    mock_message.chat = MagicMock(id=12345)
    mock_message.answer = AsyncMock()
    mock_bot = MagicMock()

    await handle_text_message(mock_message, mock_bot)

    # Verify inline keyboard was sent
    mock_message.answer.assert_awaited_once()
    call_args = mock_message.answer.call_args
    assert "Confirmation Required (Tier 2)" in call_args[0][0]
    keyboard = call_args[1]["reply_markup"]
    assert len(keyboard.inline_keyboard[0]) == 2
    approve_btn = keyboard.inline_keyboard[0][0]
    assert approve_btn.text == "✅ Approve"
    action_id = approve_btn.callback_data.split(":", 1)[1]
    assert action_id in PENDING_APPROVALS

    # Test Cancel
    cancel_query = MagicMock(spec=CallbackQuery)
    cancel_query.data = f"cancel:{action_id}"
    cancel_query.message = MagicMock()
    cancel_query.message.edit_text = AsyncMock()
    cancel_query.answer = AsyncMock()

    await handle_cancel_callback(cancel_query)
    assert action_id not in PENDING_APPROVALS
    cancel_query.message.edit_text.assert_awaited_once()
    assert "Cancelled" in cancel_query.message.edit_text.call_args[0][0]


# =====================================================================
# 6. Tier 3 PIN Verification with Immediate Message Deletion
# =====================================================================


@pytest.mark.asyncio
async def test_tier_3_pin_flow_with_deletion(setup_db):
    """Verify Tier 3 requests PIN, deletes PIN message instantly, and verifies."""
    owner_id = get_settings().OWNER_TELEGRAM_ID
    chat_id = 12345

    # 1. Trigger Tier 3 command
    mock_message = MagicMock(spec=Message)
    mock_message.text = "delete junk.txt"
    mock_message.from_user = MagicMock(id=owner_id)
    mock_message.chat = MagicMock(id=chat_id)
    mock_message.answer = AsyncMock()
    mock_bot = MagicMock()
    mock_bot.delete_message = AsyncMock()
    mock_bot.send_message = AsyncMock()

    await handle_text_message(mock_message, mock_bot)

    # Assert user was asked for PIN
    assert owner_id in PENDING_PIN_ACTIONS
    assert "PIN Verification Required" in mock_message.answer.call_args[0][0]

    # 2. User sends wrong PIN
    wrong_pin_msg = MagicMock(spec=Message)
    wrong_pin_msg.text = "YES 9999"
    wrong_pin_msg.from_user = MagicMock(id=owner_id)
    wrong_pin_msg.chat = MagicMock(id=chat_id)
    wrong_pin_msg.message_id = 777
    wrong_pin_msg.answer = AsyncMock()

    await handle_text_message(wrong_pin_msg, mock_bot)

    # PIN message must be deleted IMMEDIATELY
    mock_bot.delete_message.assert_awaited_with(chat_id=chat_id, message_id=777)
    wrong_pin_msg.answer.assert_awaited_once()
    assert "Incorrect PIN" in wrong_pin_msg.answer.call_args[0][0]
    assert owner_id not in PENDING_PIN_ACTIONS


@pytest.mark.asyncio
async def test_tier_3_correct_pin_executes(setup_db):
    """Verify correct PIN executes the pending tool call."""
    owner_id = get_settings().OWNER_TELEGRAM_ID
    chat_id = 12345
    settings = get_settings()

    # Pre-populate pending pin action
    PENDING_PIN_ACTIONS[owner_id] = ToolCall(
        tool_name="reboot_system",
        args={},
        tier=SecurityTier.TIER_3_PIN,
    )

    correct_msg = MagicMock(spec=Message)
    correct_msg.text = f"YES {settings.SAFETY_PIN}"
    correct_msg.from_user = MagicMock(id=owner_id)
    correct_msg.chat = MagicMock(id=chat_id)
    correct_msg.message_id = 888
    correct_msg.answer = AsyncMock()
    mock_bot = MagicMock()
    mock_bot.delete_message = AsyncMock()
    mock_bot.send_message = AsyncMock()

    await handle_text_message(correct_msg, mock_bot)

    # Verify PIN message was deleted
    mock_bot.delete_message.assert_awaited_with(chat_id=chat_id, message_id=888)
    # Tool executed (reboot simulated message sent)
    assert owner_id not in PENDING_PIN_ACTIONS
    mock_bot.send_message.assert_awaited()


# =====================================================================
# 7. Tier 4 Hard Blocked Tests
# =====================================================================


@pytest.mark.asyncio
async def test_tier_4_blocked_rejection(setup_db):
    """Verify Tier 4 commands are rejected immediately and logged."""
    mock_message = MagicMock(spec=Message)
    mock_message.text = "run format C:"
    mock_message.from_user = MagicMock(id=get_settings().OWNER_TELEGRAM_ID)
    mock_message.chat = MagicMock(id=12345)
    mock_message.answer = AsyncMock()
    mock_bot = MagicMock()

    await handle_text_message(mock_message, mock_bot)

    mock_message.answer.assert_awaited_once()
    assert "ACTION BLOCKED" in mock_message.answer.call_args[0][0]

    # Verify in audit log
    logs = await db.get_audit_logs(limit=1)
    assert len(logs) == 1
    assert logs[0]["status"] == "BLOCKED"
    assert logs[0]["tier"] == 4


# =====================================================================
# 8. Sandbox Fixture Tests
# =====================================================================


def test_ensure_sandbox_fixtures_creates_sample_pdf():
    """Verify ensure_sandbox_fixtures sets up test_resume.pdf."""
    sandbox_dir = ensure_sandbox_fixtures()
    assert sandbox_dir.exists()
    resume_file = sandbox_dir / "test_resume.pdf"
    assert resume_file.exists()
    assert resume_file.stat().st_size > 0
