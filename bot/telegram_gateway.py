"""Telegram Gateway for PocketPC Agent using aiogram v3.x.

Features:
1. OwnerOnlyMiddleware: Silently drops any event not originating from OWNER_TELEGRAM_ID.
2. /stop Panic Command: Sets SYSTEM_LOCKED = True, cancels active child tasks, refuses remote commands.
3. /learn and /undo commands.
4. 4-Tier Permission Handling:
   - Tier 1: Auto-execute, returning photos/files via FSInputFile.
   - Tier 2: Inline keyboard confirmation ([Approve] / [Cancel]).
   - Tier 3: Sensitive action requiring 'YES <PIN>', with instant PIN message deletion.
   - Tier 4: Hard-blocked and logged to audit_log.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
from pathlib import Path
import re
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Union
import uuid

from aiogram import BaseMiddleware, Bot, F, Router
from aiogram.filters import Command
from aiogram.types import (
    CallbackQuery,
    FSInputFile,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    Message,
    ReplyKeyboardMarkup,
    TelegramObject,
)

from core.config import get_settings
from core import db
from core.fast_router import ToolCall, route_command, route_command_chain
from core.permissions import SecurityTier
from core import sandbox
from core import keep_awake
from core.ai_planner import AIPlanner, PlannerResult, execute_tool_locally
from core import skills
from tools import system_tools, dev_services

logger = logging.getLogger(__name__)

# Global system state
SYSTEM_LOCKED: bool = False
ACTIVE_TASKS: Set[asyncio.Task] = set()

# Pending approvals for Tier 2 and Tier 3
PENDING_APPROVALS: Dict[str, ToolCall] = {}
PENDING_PIN_ACTIONS: Dict[int, ToolCall] = {}

# Pending command queue for compound command chaining: user_id -> list[str]
PENDING_COMMAND_QUEUE: Dict[int, List[str]] = {}

CHAIN_SPLIT_RE = re.compile(
    r"\s+(?:and\s+then|and\s+also|then|and|also)\s+(?=(?:start|run|launch|stop|kill|expose|tunnel|share|delete|remove|move|send|find|list|show|capture|take|status|screenshot)\b)",
    re.IGNORECASE,
)


def split_compound_command(text: str) -> List[str]:
    """Split compound commands on conjunctions when followed by an action verb."""
    if not text or not text.strip():
        return []
    parts = [p.strip() for p in CHAIN_SPLIT_RE.split(text.strip()) if p.strip()]
    return parts if parts else [text.strip()]

# Active planner sessions paused for user approval: user_id -> (AIPlanner, PlannerResult)
PENDING_PLANNER_SESSIONS: Dict[int, Any] = {}
# Recent successful tool chains for saving as skills: user_id -> list[ToolCall]
RECENT_TOOL_CHAINS: Dict[int, List[ToolCall]] = {}
# Track recent search matches per user for instant reference and download buttons
LAST_SEARCH_RESULTS: Dict[int, List[Dict[str, Any]]] = {}
# Number of files displayed per page in directory explorer inline keyboard
FILES_PER_PAGE: int = 8

# Short-lived in-memory map from short_id -> absolute file path for inline download buttons
ACTIVE_FILE_BUTTONS: Dict[str, str] = {}

# Active directory exploration sessions for pagination and bulk zip:
# session_id -> {"dir_path": str, "files": List[str], "page": int}
ACTIVE_DIR_SESSIONS: Dict[str, Dict[str, Any]] = {}


def register_file_button(file_path: Union[str, Path]) -> str:
    """Register an absolute file path and return a unique short ID for callback_data."""
    short_id = uuid.uuid4().hex[:8]
    ACTIVE_FILE_BUTTONS[short_id] = str(Path(file_path).resolve())
    if len(ACTIVE_FILE_BUTTONS) > 2000:
        for k in list(ACTIVE_FILE_BUTTONS.keys())[:500]:
            ACTIVE_FILE_BUTTONS.pop(k, None)
    return short_id


def build_dir_keyboard(session_id: str, page: int = 0) -> Optional[InlineKeyboardMarkup]:
    """Build paginated inline keyboard for a directory exploration session.

    - Row 1: [📦 Send All (Zip)] -> callback: zipdir:{session_id}
    - Rows 2-9: [📥 {filename}] -> callback: sendfile:{session_id}:{file_index}
    - Row 10: Pagination controls ([⬅️ Prev], [ page / total ], [Next ➡️])
    """
    session = ACTIVE_DIR_SESSIONS.get(session_id)
    if not session:
        return None

    files = session.get("files", [])
    if not files:
        return None

    total_files = len(files)
    total_pages = (total_files + FILES_PER_PAGE - 1) // FILES_PER_PAGE
    page = max(0, min(page, total_pages - 1))
    session["page"] = page

    keyboard_rows: List[List[InlineKeyboardButton]] = []

    # Row 1 (Bulk Action): Send All as Zip
    keyboard_rows.append([
        InlineKeyboardButton(
            text="📦 Send All (Zip)",
            callback_data=f"zipdir:{session_id}",
        )
    ])

    # Rows 2-9 (File Buttons): Slice files for current page
    start_idx = page * FILES_PER_PAGE
    end_idx = min(start_idx + FILES_PER_PAGE, total_files)
    page_files = files[start_idx:end_idx]

    dir_path = Path(session["dir_path"])
    for i, fname in enumerate(page_files):
        file_index = start_idx + i
        display_name = fname[:30] if len(fname) > 30 else fname
        cb_data = f"sendfile:{session_id}:{file_index}"
        keyboard_rows.append([
            InlineKeyboardButton(
                text=f"📥 {display_name}",
                callback_data=cb_data,
            )
        ])
        # Also register in ACTIVE_FILE_BUTTONS for backward compatibility
        full_file_path = dir_path / fname
        ACTIVE_FILE_BUTTONS[f"{session_id}_{file_index}"] = str(full_file_path.resolve())

    # Row 10 (Pagination Controls):
    if total_pages > 1:
        nav_buttons: List[InlineKeyboardButton] = []
        if page > 0:
            nav_buttons.append(
                InlineKeyboardButton(
                    text="⬅️ Prev",
                    callback_data=f"page:{session_id}:{page - 1}",
                )
            )

        nav_buttons.append(
            InlineKeyboardButton(
                text=f" {page + 1} / {total_pages} ",
                callback_data="ignore",
            )
        )

        if page < total_pages - 1:
            nav_buttons.append(
                InlineKeyboardButton(
                    text="Next ➡️",
                    callback_data=f"page:{session_id}:{page + 1}",
                )
            )

        keyboard_rows.append(nav_buttons)

    return InlineKeyboardMarkup(inline_keyboard=keyboard_rows)


def build_explore_inline_keyboard(res: Dict[str, Any]) -> Optional[InlineKeyboardMarkup]:
    """Generate inline download buttons with pagination and 'Send All as Zip' for explore_path results.

    Stores session in ACTIVE_DIR_SESSIONS and delegates to build_dir_keyboard(session_id, page=0).
    """
    if not isinstance(res, dict) or res.get("type") != "directory":
        return None

    files = res.get("files", [])
    if not files:
        return None

    dir_path = Path(res.get("path", "")).resolve()
    session_id = uuid.uuid4().hex[:8]

    file_names = [f["name"] if isinstance(f, dict) else str(f) for f in files]
    ACTIVE_DIR_SESSIONS[session_id] = {
        "dir_path": str(dir_path),
        "files": file_names,
        "page": 0,
    }

    if len(ACTIVE_DIR_SESSIONS) > 1000:
        for k in list(ACTIVE_DIR_SESSIONS.keys())[:300]:
            ACTIVE_DIR_SESSIONS.pop(k, None)

    return build_dir_keyboard(session_id, page=0)

# Persistent 1-tap quick action keyboard
QUICK_ACTION_KB = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="📸 Screenshot"), KeyboardButton(text="📊 Status")],
        [KeyboardButton(text="📋 Services"), KeyboardButton(text="☕ Caffeinate")],
        [KeyboardButton(text="🔍 Find File"), KeyboardButton(text="↩️ Undo")],
    ],
    resize_keyboard=True,
    is_persistent=True,
)
MAIN_MENU_KEYBOARD = QUICK_ACTION_KB


async def render_planner_approval_prompt(
    bot: Bot,
    chat_id: int,
    user_id: int,
    planner: AIPlanner,
    planner_res: PlannerResult,
    message: Optional[Message] = None,
) -> None:
    """Send Tier 2 inline approval keyboard or Tier 3 PIN prompt for a paused planner tool call."""
    PENDING_PLANNER_SESSIONS[user_id] = (planner, planner_res)
    paused_tc = getattr(planner_res, "pending_tool_call", None) or planner_res.paused_tool_call
    if not paused_tc:
        return

    tier = getattr(planner_res, "tier", None) or paused_tc.tier

    if tier == SecurityTier.TIER_2_CONFIRM:
        approval_id = uuid.uuid4().hex[:8]
        PENDING_APPROVALS[approval_id] = paused_tc
        formatted_args = "\n".join(f"• *{k}*: `{v}`" for k, v in paused_tc.args.items()) or "None"
        keyboard = InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    InlineKeyboardButton(text="✅ Approve", callback_data=f"approve:{approval_id}"),
                    InlineKeyboardButton(text="❌ Cancel", callback_data=f"cancel:{approval_id}"),
                ]
            ]
        )
        prompt_text = (
            f"⚠️ *Confirmation Required for AI Plan (Tier 2)*\n\n"
            f"Action: `{paused_tc.tool_name}`\n"
            f"{formatted_args}\n\n"
            f"Do you approve this action?"
        )
        if message:
            await message.answer(prompt_text, reply_markup=keyboard, parse_mode="Markdown")
        else:
            await bot.send_message(chat_id, prompt_text, reply_markup=keyboard, parse_mode="Markdown")
        return

    if tier == SecurityTier.TIER_3_PIN:
        PENDING_PIN_ACTIONS[user_id] = paused_tc
        formatted_args = "\n".join(f"• *{k}*: `{v}`" for k, v in paused_tc.args.items()) or "None"
        prompt_text = (
            f"🔐 *PIN Verification Required for AI Plan (Tier 3)*\n\n"
            f"Action: `{paused_tc.tool_name}`\n"
            f"{formatted_args}\n\n"
            f"⚠️ Privileged/destructive action requested by AI Planner.\n"
            f"To proceed, reply with:\n"
            f"`YES <PIN>`\n\n"
            f"_(Your reply will be immediately deleted for privacy)_"
        )
        if message:
            await message.answer(prompt_text, parse_mode="Markdown")
        else:
            await bot.send_message(chat_id, prompt_text, parse_mode="Markdown")
        return


def is_system_locked() -> bool:
    """Return whether the agent is currently locked."""
    return SYSTEM_LOCKED


def lock_system() -> None:
    """Lock the system, kill running tasks, and wipe pending approvals."""
    global SYSTEM_LOCKED
    SYSTEM_LOCKED = True

    # Cancel all tracked active tasks
    for task in list(ACTIVE_TASKS):
        if not task.done():
            task.cancel()
    ACTIVE_TASKS.clear()

    # Clear pending approvals and queued commands
    PENDING_APPROVALS.clear()
    PENDING_PIN_ACTIONS.clear()
    PENDING_COMMAND_QUEUE.clear()
    PENDING_PLANNER_SESSIONS.clear()


def unlock_system() -> None:
    """Unlock the system locally."""
    global SYSTEM_LOCKED
    SYSTEM_LOCKED = False


# =====================================================================
# Middleware: Owner-Only Lock
# =====================================================================


class OwnerOnlyMiddleware(BaseMiddleware):
    """Enforce Owner-Only Lock: silently drop any event not from OWNER_TELEGRAM_ID."""

    def __init__(self, owner_id: int):
        super().__init__()
        self.owner_id = owner_id

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        user = data.get("event_from_user")
        if not user or user.id != self.owner_id:
            logger.warning(
                "Unauthorized access attempt dropped from user_id=%s",
                user.id if user else "Unknown",
            )
            # Drop silently per Rule 1
            return None
        return await handler(event, data)


# Router definition
router = Router(name="telegram_gateway")


# =====================================================================
# Tool Executor Helper
# =====================================================================


async def execute_shell_command(command: str, timeout: float = 30.0) -> str:
    """Execute a shell command asynchronously with an explicit timeout and AV resilience."""
    res = await system_tools.run_shell(command, timeout=timeout)
    if res.get("status") == "error":
        return f"⚠️ {res.get('message', 'Shell execution failed.')}"
    return res.get("output", res.get("message", "(Command finished with no output)"))


async def execute_tool_call(tool_call: ToolCall, bot: Bot, chat_id: int) -> None:
    """Execute the given ToolCall and reply to user with the results."""
    tool_name = tool_call.tool_name
    args = tool_call.args

    try:
        if tool_name == "get_system_vitals":
            vitals = await system_tools.get_system_vitals()
            await bot.send_message(chat_id, vitals["formatted"])
            await db.log_audit(command="get_system_vitals", tier=1, status="SUCCESS")

        elif tool_name == "capture_screenshot":
            screenshot_path = await system_tools.capture_screenshot()
            photo = FSInputFile(str(screenshot_path))
            await bot.send_photo(
                chat_id,
                photo,
                caption=f"📸 Screenshot captured: `{screenshot_path.name}`",
                parse_mode="Markdown",
            )
            await db.log_audit(
                command="capture_screenshot",
                tier=1,
                status="SUCCESS",
                details=str(screenshot_path),
            )

        elif tool_name == "find_files":
            query = args.get("query", "")
            matches = await system_tools.find_files(query)
            if not matches:
                await bot.send_message(chat_id, f"🔍 No files found matching `{query}`.", parse_mode="Markdown")
            else:
                LAST_SEARCH_RESULTS[chat_id] = matches
                lines = [f"🔍 Found {len(matches)} matching file(s) for `{query}`:"]
                inline_buttons = []
                for i, m in enumerate(matches, 1):
                    lines.append(f"{i}. *{m['name']}* ({m['size_formatted']})\n   `{m['path']}`")
                    inline_buttons.append([
                        InlineKeyboardButton(
                            text=f"📥 Send #{i}: {m['name'][:22]}",
                            callback_data=f"sendfile:{i-1}",
                        )
                    ])
                reply_markup = InlineKeyboardMarkup(inline_keyboard=inline_buttons) if inline_buttons else None
                await bot.send_message(chat_id, "\n".join(lines), reply_markup=reply_markup, parse_mode="Markdown")
            await db.log_audit(command=f"find_files {query}", tier=1, status="SUCCESS")

        elif tool_name == "explore_path":
            target = args.get("target") or args.get("path") or args.get("folder") or "."
            try:
                res = await system_tools.explore_path(target)
                inline_keyboard = build_explore_inline_keyboard(res)
                await bot.send_message(chat_id, res["formatted"], reply_markup=inline_keyboard, parse_mode="Markdown")
                await db.log_audit(command=f"explore_path {target}", tier=1, status="SUCCESS")
            except PermissionError as pe:
                await bot.send_message(chat_id, f"🚫 Access denied: `{str(pe)}`", parse_mode="Markdown")
                await db.log_audit(command=f"explore_path {target}", tier=1, status="BLOCKED", details=str(pe))
            except FileNotFoundError as fe:
                await bot.send_message(chat_id, f"🔍 {str(fe)}", parse_mode="Markdown")
                await db.log_audit(command=f"explore_path {target}", tier=1, status="FAILED", details=str(fe))
            except Exception as e:
                await bot.send_message(chat_id, f"❌ Error exploring path: `{str(e)}`", parse_mode="Markdown")
                await db.log_audit(command=f"explore_path {target}", tier=1, status="FAILED", details=str(e))

        elif tool_name == "deliver_path":
            target = args.get("target") or args.get("path") or args.get("file") or ""
            try:
                res = await system_tools.deliver_path(target, bot=bot, chat_id=chat_id)
                await bot.send_message(chat_id, res, parse_mode="Markdown")
                await db.log_audit(command=f"deliver_path {target}", tier=1, status="SUCCESS")
            except PermissionError as pe:
                await bot.send_message(chat_id, f"🚫 Access denied: `{str(pe)}`", parse_mode="Markdown")
                await db.log_audit(command=f"deliver_path {target}", tier=1, status="BLOCKED", details=str(pe))
            except FileNotFoundError as fe:
                await bot.send_message(chat_id, f"🔍 {str(fe)}", parse_mode="Markdown")
                await db.log_audit(command=f"deliver_path {target}", tier=1, status="FAILED", details=str(fe))
            except Exception as e:
                await bot.send_message(chat_id, f"❌ Error delivering path: `{str(e)}`", parse_mode="Markdown")
                await db.log_audit(command=f"deliver_path {target}", tier=1, status="FAILED", details=str(e))

        elif tool_name == "list_directory":
            path = args.get("path") or args.get("folder") or args.get("directory") or "."
            folders_only = bool(args.get("folders_only", False))
            files_only = bool(args.get("files_only", False))
            try:
                res = await system_tools.list_directory(path, folders_only=folders_only, files_only=files_only)
                await bot.send_message(chat_id, res["formatted"], parse_mode="Markdown")
                await db.log_audit(command=f"list_directory {path}", tier=1, status="SUCCESS")
            except PermissionError as pe:
                await bot.send_message(chat_id, f"🚫 Access denied: `{str(pe)}`", parse_mode="Markdown")
                await db.log_audit(command=f"list_directory {path}", tier=1, status="BLOCKED", details=str(pe))
            except FileNotFoundError as fe:
                await bot.send_message(chat_id, f"🔍 {str(fe)}", parse_mode="Markdown")
                await db.log_audit(command=f"list_directory {path}", tier=1, status="FAILED", details=str(fe))
            except Exception as e:
                await bot.send_message(chat_id, f"❌ Error listing directory: `{str(e)}`", parse_mode="Markdown")
                await db.log_audit(command=f"list_directory {path}", tier=1, status="FAILED", details=str(e))

        elif tool_name == "send_file":
            target = args.get("target", "").strip()
            # If target is generic (e.g. "it", "this", "the file", "last"), check last search results
            if target.lower() in ("it", "last", "this", "the file", ""):
                last_matches = LAST_SEARCH_RESULTS.get(chat_id, [])
                if last_matches:
                    target = last_matches[0]["path"]
                else:
                    await bot.send_message(
                        chat_id,
                        "ℹ️ Please specify the filename to send (e.g. `send resume.pdf`).",
                        parse_mode="Markdown",
                    )
                    return

            try:
                resolved_file = await system_tools.resolve_file_for_sending(target)
                doc = FSInputFile(str(resolved_file))
                size_str = system_tools._format_size(resolved_file.stat().st_size)
                await bot.send_document(
                    chat_id,
                    doc,
                    caption=f"📄 Delivered: `{resolved_file.name}` ({size_str})",
                    parse_mode="Markdown",
                )
                LAST_SEARCH_RESULTS[chat_id] = [{
                    "path": str(resolved_file),
                    "name": resolved_file.name,
                    "size_formatted": size_str,
                }]
                await db.log_audit(command=f"send_file {target}", tier=1, status="SUCCESS", details=str(resolved_file))
            except PermissionError as pe:
                await bot.send_message(chat_id, f"🚫 Access denied: `{str(pe)}`", parse_mode="Markdown")
            except FileNotFoundError:
                await bot.send_message(chat_id, f"🔍 Could not find `{target}` inside allowed folders.", parse_mode="Markdown")
            except Exception as e:
                await bot.send_message(chat_id, f"❌ Error sending file: `{str(e)}`", parse_mode="Markdown")

        elif tool_name == "send_folder_files":
            folder = args.get("folder", "").strip()
            cat = args.get("category", "images").strip()
            try:
                pkg = await system_tools.package_folder_files(folder, category=cat)
                if pkg["file_count"] == 0:
                    await bot.send_message(
                        chat_id,
                        f"ℹ️ No {pkg['category']} found in folder `{pkg['folder_name']}`.",
                        parse_mode="Markdown",
                    )
                elif pkg["file_count"] == 1 and pkg["sample_files"]:
                    single_file = Path(pkg["sample_files"][0])
                    doc = FSInputFile(str(single_file))
                    size_str = system_tools._format_size(single_file.stat().st_size)
                    if single_file.suffix.lower() in system_tools.IMAGE_EXTENSIONS:
                        await bot.send_photo(
                            chat_id,
                            doc,
                            caption=f"🖼️ Delivered: `{single_file.name}` ({size_str}) from `{pkg['folder_name']}`",
                            parse_mode="Markdown",
                        )
                    else:
                        await bot.send_document(
                            chat_id,
                            doc,
                            caption=f"📄 Delivered: `{single_file.name}` ({size_str}) from `{pkg['folder_name']}`",
                            parse_mode="Markdown",
                        )
                else:
                    # Multi-file package
                    # If images, send a photo preview of the first image
                    if pkg["category"] == "images" and pkg["sample_files"]:
                        preview_file = Path(pkg["sample_files"][0])
                        try:
                            await bot.send_photo(
                                chat_id,
                                FSInputFile(str(preview_file)),
                                caption=f"🖼️ Preview: `{preview_file.name}` (1 of {pkg['file_count']} {pkg['category']})",
                                parse_mode="Markdown",
                            )
                        except Exception:
                            pass

                    # Send zip archive
                    zip_doc = FSInputFile(str(pkg["zip_path"]))
                    await bot.send_document(
                        chat_id,
                        zip_doc,
                        caption=f"📦 Delivered: `{pkg['zip_path'].name}`\n📁 {pkg['file_count']} {pkg['category']} from `{pkg['folder_name']}` ({pkg['total_formatted']})",
                        parse_mode="Markdown",
                    )
                await db.log_audit(command=f"send_folder_files {folder} {cat}", tier=1, status="SUCCESS", details=str(pkg.get("zip_path", "")))
            except PermissionError as pe:
                await bot.send_message(chat_id, f"🚫 Access denied: `{str(pe)}`", parse_mode="Markdown")
            except FileNotFoundError as fe:
                await bot.send_message(chat_id, f"🔍 {str(fe)}", parse_mode="Markdown")
            except Exception as e:
                await bot.send_message(chat_id, f"❌ Error packaging folder files: `{str(e)}`", parse_mode="Markdown")

        elif tool_name == "safe_delete":
            target_path = args.get("target_path", "")
            res = await sandbox.safe_delete(target_path)
            if res.get("status") == "error":
                await bot.send_message(chat_id, f"⚠️ {res['message']}", parse_mode="Markdown")
            else:
                await bot.send_message(
                    chat_id,
                    f"🗑️ Safely deleted `{res['original_path']}`\n"
                    f"Moved to undo storage (Undo ID: {res['undo_id']}).\n"
                    f"Send /undo to restore.",
                    parse_mode="Markdown",
                )

        elif tool_name == "safe_move":
            src = args.get("src", "")
            dst = args.get("dst", "")
            res = await sandbox.safe_move(src, dst)
            if res.get("status") == "error":
                await bot.send_message(chat_id, f"⚠️ {res['message']}", parse_mode="Markdown")
            else:
                await bot.send_message(
                    chat_id,
                    f"📦 Moved `{res['original_path']}` to `{res['destination_path']}`.\n"
                    f"Backup preserved in undo storage (Undo ID: {res['undo_id']}).",
                    parse_mode="Markdown",
                )

        elif tool_name == "zip_and_prepare":
            path = args.get("path", "")
            zip_path = await system_tools.zip_and_prepare(path)
            doc = FSInputFile(str(zip_path))
            await bot.send_document(
                chat_id,
                doc,
                caption=f"📁 Archive prepared: `{zip_path.name}`",
                parse_mode="Markdown",
            )
            await db.log_audit(command=f"zip_and_prepare {path}", tier=2, status="SUCCESS")

        elif tool_name == "undo_last_action":
            res = await sandbox.undo_last_action()
            if res:
                await bot.send_message(
                    chat_id,
                    f"↩️ Successfully restored {res['action_type']} for `{res['original_path']}`.",
                    parse_mode="Markdown",
                )
            else:
                await bot.send_message(chat_id, "ℹ️ Nothing to undo. No pending un-restored actions found.")

        elif tool_name == "run_shell":
            cmd = args.get("command", "")
            output = await execute_shell_command(cmd)
            # Split if output is very long
            snippet = output[:3500] if len(output) > 3500 else output
            await bot.send_message(
                chat_id,
                f"💻 Shell output for `{cmd}`:\n```\n{snippet}\n```",
                parse_mode="Markdown",
            )
            await db.log_audit(command=f"run_shell {cmd}", tier=3, status="SUCCESS")

        elif tool_name == "kill_process":
            pid_raw = args.get("pid") or args.get("target", "")
            res = await system_tools.kill_process(pid_raw)
            if res.get("status") == "success":
                await bot.send_message(chat_id, f"🔪 {res['message']}", parse_mode="Markdown")
                await db.log_audit(command=f"kill_process {pid_raw}", tier=3, status="SUCCESS")
            else:
                await bot.send_message(chat_id, f"⚠️ {res['message']}", parse_mode="Markdown")
                await db.log_audit(command=f"kill_process {pid_raw}", tier=3, status="FAILED", details=res.get("message"))

        elif tool_name == "reboot_system":
            await bot.send_message(chat_id, "🔄 System reboot requested. (Simulated in dry-run mode for safety).")
            await db.log_audit(command="reboot_system", tier=3, status="SUCCESS")

        elif tool_name == "stop_service":
            await bot.send_message(chat_id, "⏹️ Operation stopped.")
            await db.log_audit(command="stop_service", tier=2, status="SUCCESS")

        elif tool_name == "list_running_services":
            res = await dev_services.list_running_services()
            await bot.send_message(chat_id, res["formatted"], parse_mode="Markdown")
            await db.log_audit(command="list_running_services", tier=1, status="SUCCESS")

        elif tool_name == "start_named_service":
            svc = args.get("target") or args.get("service_name", "")
            comp = args.get("component")
            res = await dev_services.start_named_service(target=svc, component=comp)
            await bot.send_message(chat_id, res["message"], parse_mode="Markdown")
            await db.log_audit(command=f"start_named_service {svc} {comp or ''}", tier=2, status="SUCCESS")

        elif tool_name == "stop_named_service":
            svc = args.get("target") or args.get("service_name", "")
            res = await dev_services.stop_named_service(target=svc)
            await bot.send_message(chat_id, res["message"], parse_mode="Markdown")
            await db.log_audit(command=f"stop_named_service {svc}", tier=2, status="SUCCESS")

        elif tool_name == "get_service_logs":
            svc = args.get("service_name", "")
            logs = dev_services.get_service_logs(svc)
            await bot.send_message(chat_id, f"📋 *Logs for `{svc}`:*\n```\n{logs[-3500:]}\n```", parse_mode="Markdown")
            await db.log_audit(command=f"get_service_logs {svc}", tier=1, status="SUCCESS")

        elif tool_name == "expose_port_tunnel":
            port = int(args.get("port", 8000))
            res = await dev_services.expose_port_tunnel(port)
            await bot.send_message(chat_id, res["message"], parse_mode="Markdown")
            await db.log_audit(command=f"expose_port_tunnel {port}", tier=2, status="SUCCESS", details=res.get("url", ""))

        elif tool_name == "caffeinate_toggle":
            state = args.get("state", "on").lower()
            if state == "on":
                keep_awake.enable_keep_awake()
                await bot.send_message(chat_id, "☕ *Sleep Prevention Enabled.* Laptop will stay awake.", parse_mode="Markdown")
            else:
                keep_awake.disable_keep_awake()
                await bot.send_message(chat_id, "💤 *Sleep Prevention Disabled.* Standard sleep restored.", parse_mode="Markdown")
            await db.log_audit(command=f"caffeinate {state}", tier=2, status="SUCCESS")

        elif tool_name == "caffeinate_status":
            is_on = keep_awake.is_keep_awake_enabled()
            status_str = "Active ☕" if is_on else "Inactive 💤"
            await bot.send_message(chat_id, f"☕ *Caffeinate Status:* {status_str}", parse_mode="Markdown")
            await db.log_audit(command="caffeinate status", tier=1, status="SUCCESS")

        else:
            await bot.send_message(chat_id, f"⚠️ Unknown tool `{tool_name}`.", parse_mode="Markdown")

    except Exception as e:
        logger.error("Error executing tool %s: %s", tool_name, e, exc_info=True)
        PENDING_COMMAND_QUEUE.pop(chat_id, None)
        await bot.send_message(chat_id, f"❌ Execution error: `{str(e)}`", parse_mode="Markdown")
        await db.log_audit(
            command=f"{tool_name} {args}",
            tier=int(tool_call.tier),
            status="FAILED",
            details=str(e),
        )


# =====================================================================
# Command Handlers
# =====================================================================


@router.message(Command("start", "menu"))
async def handle_start(message: Message) -> None:
    """Welcome message and system status with quick action menu."""
    await message.answer(
        "🖥️ **PocketPC Agent Active**\n\nSystem locked & secure. Use the menu below or type a command.",
        reply_markup=QUICK_ACTION_KB,
        parse_mode="Markdown",
    )


@router.message(Command("stop"))
async def handle_stop(message: Message) -> None:
    """Panic command: Emergency lock and kill all active child tasks."""
    lock_system()
    await db.log_audit(command="/stop", tier=2, status="SYSTEM_LOCKED", details="Panic stop triggered")
    await message.answer(
        "🚨 *EMERGENCY STOP ACTIVATED*\n\n"
        "• System status: *LOCKED*\n"
        "• Active child tasks: *KILLED*\n"
        "• Pending actions: *CLEARED*\n\n"
        "The agent will refuse all commands until unlocked locally on the host machine.",
        parse_mode="Markdown",
    )


@router.message(Command("unlock"))
async def handle_unlock(message: Message) -> None:
    """Local unlock command: Unlocks the system if provided correct safety PIN."""
    text = (message.text or "").strip()
    parts = text.split(maxsplit=1)
    pin = parts[1] if len(parts) > 1 else ""

    settings = get_settings()
    if pin == settings.SAFETY_PIN:
        unlock_system()
        # Delete user PIN message immediately
        try:
            await message.delete()
        except Exception:
            pass
        await message.answer("🔓 *System Unlocked.* Remote control resumed.", parse_mode="Markdown")
        await db.log_audit(command="/unlock", tier=3, status="UNLOCKED")
    else:
        try:
            await message.delete()
        except Exception:
            pass
        await message.answer("❌ Invalid PIN. System remains locked.", parse_mode="Markdown")


@router.message(Command("undo"))
async def handle_undo(message: Message, bot: Bot) -> None:
    """Trigger undo_last_action immediately."""
    if is_system_locked():
        await message.answer("🚨 System is locked. Unlock locally to resume.")
        return

    tool_call = ToolCall(tool_name="undo_last_action", args={}, tier=SecurityTier.TIER_1_AUTO)
    await execute_tool_call(tool_call, bot, message.chat.id)


@router.message(F.text.regexp(r"^/learn\s+(.+?)\s*=\s*(.+)$"))
@router.message(F.text.regexp(r"^learn\s+(.+?)\s*=\s*(.+)$"))
async def handle_learn(message: Message) -> None:
    """Save custom user shortcut to SQLite shortcuts table."""
    if is_system_locked():
        await message.answer("🚨 System is locked. Unlock locally to resume.")
        return

    match = re.match(r"^(?:/learn|learn)\s+(.+?)\s*=\s*(.+)$", message.text.strip(), re.IGNORECASE)
    if not match:
        await message.answer("⚠️ Usage: `/learn <alias> = <command>`", parse_mode="Markdown")
        return

    alias = match.group(1).strip()
    target_command = match.group(2).strip()

    await db.add_shortcut(alias, target_command)
    await db.log_audit(
        command=f"learn {alias} = {target_command}",
        tier=2,
        status="SUCCESS",
        details="Added custom shortcut",
    )
    await message.answer(
        f"✅ *Shortcut Learned!*\n\n• Trigger: `{alias}`\n• Mapped to: `{target_command}`",
        parse_mode="Markdown",
    )


@router.message(Command("skills"))
async def handle_list_skills(message: Message) -> None:
    """List all saved multi-step skills."""
    if is_system_locked():
        await message.answer("🚨 System is locked. Unlock locally to resume.")
        return

    saved = await skills.list_skills()
    if not saved:
        await message.answer(
            "📋 *No Saved Skills Found*\n\n"
            "You can save successful multi-step workflows using `/save_skill <name>`.",
            parse_mode="Markdown",
        )
        return

    lines = ["📚 *Saved Skills:*"]
    for s in saved:
        lines.append(f"• *{s.name}*: {s.description} _({len(s.steps)} step(s))_")
    lines.append("\n_Run any skill by sending its name, or delete with `/forget <name>`._")
    await message.answer("\n".join(lines), parse_mode="Markdown")


@router.message(F.text.regexp(r"^/forget\s+(\S+)$"))
@router.message(F.text.regexp(r"^forget\s+(\S+)$"))
async def handle_forget_skill(message: Message) -> None:
    """Delete a saved skill from SQLite."""
    if is_system_locked():
        await message.answer("🚨 System is locked. Unlock locally to resume.")
        return

    parts = message.text.strip().split(maxsplit=1)
    skill_name = parts[1].strip()

    deleted = await skills.delete_skill(skill_name)
    if deleted:
        await message.answer(f"🗑️ Skill `{skill_name}` deleted successfully.", parse_mode="Markdown")
        await db.log_audit(command=f"forget {skill_name}", tier=2, status="SUCCESS")
    else:
        await message.answer(f"⚠️ Skill `{skill_name}` not found.", parse_mode="Markdown")


@router.message(F.text.regexp(r"^/save_skill\s+(\S+)(?:\s+(.*))?$"))
async def handle_save_skill_command(message: Message) -> None:
    """Save recent multi-step tool calls as a reusable named skill."""
    if is_system_locked():
        await message.answer("🚨 System is locked. Unlock locally to resume.")
        return

    match = re.match(r"^/save_skill\s+(\S+)(?:\s+(.*))?$", message.text.strip())
    if not match:
        await message.answer("⚠️ Usage: `/save_skill <name> [description]`", parse_mode="Markdown")
        return

    skill_name = match.group(1).strip()
    description = (match.group(2) or "").strip()

    recent = RECENT_TOOL_CHAINS.get(message.from_user.id, [])
    if not recent:
        await message.answer("⚠️ No recent multi-step tool chain to save.", parse_mode="Markdown")
        return

    steps = [{"tool_name": tc.tool_name, "args": tc.args} for tc in recent]
    await skills.save_skill(skill_name, steps, description=description)
    await message.answer(
        f"✅ *Skill Saved!*\n\n• Name: `{skill_name}`\n• Steps: {len(steps)}\n"
        f"Run anytime by sending `{skill_name}`.",
        parse_mode="Markdown",
    )


@router.message(Command("caffeinate"))
async def handle_caffeinate_command(message: Message, bot: Bot) -> None:
    """Toggle or check Windows sleep prevention."""
    if is_system_locked():
        await message.answer("🚨 System is locked. Unlock locally to resume.")
        return

    text = (message.text or "").strip()
    parts = text.split(maxsplit=1)
    subcmd = parts[1].lower() if len(parts) > 1 else ""

    if subcmd in ("on", "enable"):
        tool_call = ToolCall(tool_name="caffeinate_toggle", args={"state": "on"}, tier=SecurityTier.TIER_2_CONFIRM)
        await execute_tool_call(tool_call, bot, message.chat.id)
    elif subcmd in ("off", "disable"):
        tool_call = ToolCall(tool_name="caffeinate_toggle", args={"state": "off"}, tier=SecurityTier.TIER_2_CONFIRM)
        await execute_tool_call(tool_call, bot, message.chat.id)
    else:
        is_on = keep_awake.is_keep_awake_enabled()
        status_str = "Active ☕ (Laptop will not sleep)" if is_on else "Inactive 💤 (Normal sleep)"
        await message.answer(
            f"☕ *Caffeinate Status:* {status_str}\n\n"
            f"Usage: `/caffeinate on` or `/caffeinate off`",
            parse_mode="Markdown",
        )


# =====================================================================
# Command Queue & Single Command Execution
# =====================================================================


async def process_next_in_queue(message: Message, user_id: int, bot: Optional[Bot] = None) -> None:
    """Pop and execute the next sub-command from the user's pending queue."""
    queue = PENDING_COMMAND_QUEUE.get(user_id, [])
    if queue:
        next_cmd = queue.pop(0)
        await execute_single_user_command(message, user_id, next_cmd, bot=bot)


async def execute_single_user_command(
    chat_Message: Message,
    user_id: int,
    command_text: str,
    bot: Optional[Bot] = None,
) -> None:
    """Execute a single user command through fast_router, permission gate, or AIPlanner."""
    if not command_text or not command_text.strip():
        await process_next_in_queue(chat_Message, user_id, bot=bot)
        return

    if bot is None and chat_Message is not None:
        bot = getattr(chat_Message, "bot", None)

    chat_id = chat_Message.chat.id if (chat_Message and chat_Message.chat) else user_id
    raw_text = command_text.strip()

    # Map Quick Action Menu buttons to standard text commands
    button_mapping = {
        "📸 Screenshot": "screenshot",
        "📊 Status": "status",
        "☕ Caffeinate": "caffeinate status",
        "📋 Services": "services",
        "↩️ Undo": "/undo",
    }
    if raw_text == "🔍 Find File":
        await chat_Message.answer(
            "🔍 *Find or Send Files:*\n\n"
            "• `find <name>` — Search files (with instant download buttons)\n"
            "• `send <name>` — Send a file directly (e.g. `send resume.pdf`)\n\n"
            "_Tip: You can also say 'send it to me' right after a search!_",
            parse_mode="Markdown",
        )
        await process_next_in_queue(chat_Message, user_id, bot=bot)
        return
    elif raw_text in button_mapping:
        raw_text = button_mapping[raw_text]

    # 1. System Lock Guard
    if is_system_locked():
        PENDING_COMMAND_QUEUE.pop(user_id, None)
        await chat_Message.answer(
            "🚨 *SYSTEM IS LOCKED*\n\n"
            "Remote commands are disabled following an emergency stop.\n"
            "Unlock locally or send `/unlock <PIN>`.",
            parse_mode="Markdown",
        )
        return

    # 2. Check if user typed a saved skill name
    saved_skill = await skills.get_skill(raw_text)
    if saved_skill:
        await chat_Message.answer(
            f"⚡ *Executing Saved Skill:* `{saved_skill.name}` ({len(saved_skill.steps)} step(s))...",
            parse_mode="Markdown",
        )
        skill_calls = skills.steps_to_tool_calls(saved_skill)
        skill_failed = False
        for tc in skill_calls:
            if tc.tier == SecurityTier.TIER_4_BLOCKED:
                PENDING_COMMAND_QUEUE.pop(user_id, None)
                await chat_Message.answer(f"🚫 Step `{tc.tool_name}` blocked by Tier 4 security policy.")
                skill_failed = True
                break
            await execute_tool_call(tc, bot, chat_id)
        if not skill_failed:
            await process_next_in_queue(chat_Message, user_id, bot=bot)
        return

    # 3. Route via fast_router
    tool_call = await route_command(raw_text)

    # 4. If fast router matched, evaluate deterministic security tier
    if tool_call is not None:
        tier = tool_call.tier

        # Tier 1: Auto-Execute
        if tier == SecurityTier.TIER_1_AUTO:
            await execute_tool_call(tool_call, bot, chat_id)
            await process_next_in_queue(chat_Message, user_id, bot=bot)
            return

        # Tier 2: Inline Confirmation
        elif tier == SecurityTier.TIER_2_CONFIRM:
            approval_id = uuid.uuid4().hex[:8]
            PENDING_APPROVALS[approval_id] = tool_call

            formatted_args = "\n".join(f"• *{k}*: `{v}`" for k, v in tool_call.args.items()) or "None"
            keyboard = InlineKeyboardMarkup(
                inline_keyboard=[
                    [
                        InlineKeyboardButton(text="✅ Approve", callback_data=f"approve:{approval_id}"),
                        InlineKeyboardButton(text="❌ Cancel", callback_data=f"cancel:{approval_id}"),
                    ]
                ]
            )
            await chat_Message.answer(
                f"⚠️ *Confirmation Required (Tier 2)*\n\n"
                f"Action: `{tool_call.tool_name}`\n"
                f"{formatted_args}\n\n"
                f"Do you want to proceed?",
                reply_markup=keyboard,
                parse_mode="Markdown",
            )
            return

        # Tier 3: PIN Verification Required
        elif tier == SecurityTier.TIER_3_PIN:
            PENDING_PIN_ACTIONS[user_id] = tool_call
            formatted_args = "\n".join(f"• *{k}*: `{v}`" for k, v in tool_call.args.items()) or "None"
            await chat_Message.answer(
                f"🔐 *PIN Verification Required (Tier 3)*\n\n"
                f"Action: `{tool_call.tool_name}`\n"
                f"{formatted_args}\n\n"
                f"⚠️ This is a destructive or privileged command.\n"
                f"To proceed, reply with:\n"
                f"`YES <PIN>`\n\n"
                f"_(Your reply will be immediately deleted for privacy)_",
                parse_mode="Markdown",
            )
            return

        # Tier 4: Hard-Blocked
        elif tier == SecurityTier.TIER_4_BLOCKED:
            PENDING_COMMAND_QUEUE.pop(user_id, None)
            await chat_Message.answer(
                f"🚫 *ACTION BLOCKED (Tier 4)*\n\n"
                f"This command is strictly forbidden by the deterministic security gate.\n"
                f"• Tool: `{tool_call.tool_name}`\n"
                f"• Command: `{tool_call.raw_command}`",
                parse_mode="Markdown",
            )
            await db.log_audit(
                command=tool_call.raw_command,
                tier=4,
                status="BLOCKED",
                details="Hard-blocked Tier 4 command attempt",
            )
            return

    # 5. If fast router returned None, delegate to Bounded AI Planner
    await chat_Message.answer("🧠 *Consulting AI Planner...*", parse_mode="Markdown")
    planner = AIPlanner()
    planner_res = await planner.plan_and_execute(raw_text)

    if planner_res.executed_steps:
        RECENT_TOOL_CHAINS[user_id] = planner_res.executed_steps

    # Check if planner paused on a Tier 2 or Tier 3 tool call
    if planner_res.paused_for_approval and (planner_res.paused_tool_call or getattr(planner_res, "pending_tool_call", None)):
        await render_planner_approval_prompt(
            bot=bot,
            chat_id=chat_id,
            user_id=user_id,
            planner=planner,
            planner_res=planner_res,
            message=chat_Message,
        )
        return

    # Auto-deliver files if planner executed deliver_path or send_file
    for step in planner_res.executed_steps:
        if step.tool_name in ("deliver_path", "send_file"):
            target = step.args.get("target") or step.args.get("path") or ""
            try:
                await system_tools.deliver_path(target, bot=bot, chat_id=chat_id)
            except Exception as e:
                logger.warning("Could not auto-deliver file from planner step: %s", e)

    # Check if explore_path was executed in this plan and build inline download buttons
    inline_keyboard = None
    for step in planner_res.executed_steps:
        if step.tool_name in ("explore_path", "list_directory"):
            res = system_tools.LAST_EXPLORED_DATA
            if not res or res.get("type") != "directory":
                target = step.args.get("target") or step.args.get("path") or step.args.get("folder") or "."
                try:
                    res = await system_tools.explore_path(target)
                except Exception as e:
                    logger.warning("Could not explore path for buttons: %s", e)
                    res = None
            if res:
                inline_keyboard = build_explore_inline_keyboard(res)

    if planner_res.final_message:
        await chat_Message.answer(planner_res.final_message, reply_markup=inline_keyboard)

    await process_next_in_queue(chat_Message, user_id, bot=bot)


# =====================================================================
# Inline Callback Handler (Tier 2 Confirmation)
# =====================================================================


@router.callback_query(F.data.startswith("approve:"))
async def handle_approve_callback(callback: CallbackQuery, bot: Bot) -> None:
    """Execute Tier 2 action upon user pressing [Approve]."""
    if is_system_locked():
        await callback.answer("System is locked.", show_alert=True)
        return

    approval_id = callback.data.split(":", 1)[1]
    tool_call = PENDING_APPROVALS.pop(approval_id, None)

    if not tool_call:
        await callback.answer("Action expired or already handled.", show_alert=True)
        return

    await callback.answer("Action approved. Executing...")
    if callback.message:
        await callback.message.edit_text(
            f"✅ *Approved:* Executing `{tool_call.tool_name}`...",
            parse_mode="Markdown",
        )
    user = getattr(callback, "from_user", None)
    user_id = user.id if (user and hasattr(user, "id")) else (
        callback.message.chat.id if (callback.message and hasattr(callback.message, "chat") and hasattr(callback.message.chat, "id")) else 0
    )
    # If this was part of an AI Planner session, resume planning without double output
    if user_id in PENDING_PLANNER_SESSIONS:
        planner, paused_state = PENDING_PLANNER_SESSIONS.pop(user_id)
        tool_out = await execute_tool_locally(tool_call.tool_name, tool_call.args)
        await db.log_audit(
            command=f"{tool_call.tool_name} {tool_call.args}",
            tier=2,
            status="SUCCESS",
        )
        resumed_res = await planner.resume_after_approval(paused_state, tool_out)

        # Task 3.1: Render intermediate message if present
        if getattr(resumed_res, "intermediate_message", None):
            if callback.message:
                await callback.message.answer(resumed_res.intermediate_message)
            else:
                await bot.send_message(user_id, resumed_res.intermediate_message)

        # Task 3.1: Check if planner paused on subsequent Tier 2 or Tier 3 tool call
        if resumed_res.paused_for_approval:
            await render_planner_approval_prompt(
                bot=bot,
                chat_id=callback.message.chat.id if callback.message else user_id,
                user_id=user_id,
                planner=planner,
                planner_res=resumed_res,
                message=callback.message,
            )
            return

        # Task 3.1: Only if not paused and final_message
        if not resumed_res.paused_for_approval and resumed_res.final_message:
            await bot.send_message(user_id, resumed_res.final_message)

        if callback.message:
            await process_next_in_queue(callback.message, user_id, bot=bot)
    else:
        chat_id = callback.message.chat.id if callback.message else user_id
        await execute_tool_call(tool_call, bot, chat_id)
        if callback.message:
            await process_next_in_queue(callback.message, user_id, bot=bot)


@router.callback_query(F.data.startswith("cancel:"))
async def handle_cancel_callback(callback: CallbackQuery) -> None:
    """Cancel Tier 2 action upon user pressing [Cancel]."""
    user = getattr(callback, "from_user", None)
    user_id = user.id if (user and hasattr(user, "id")) else (
        callback.message.chat.id if (callback.message and hasattr(callback.message, "chat") and hasattr(callback.message.chat, "id")) else 0
    )
    PENDING_COMMAND_QUEUE.pop(user_id, None)
    approval_id = callback.data.split(":", 1)[1]
    tool_call = PENDING_APPROVALS.pop(approval_id, None)

    await callback.answer("Action cancelled.")
    if callback.message:
        tool_desc = tool_call.tool_name if tool_call else "Action"
        await callback.message.edit_text(f"❌ *Cancelled:* `{tool_desc}` was aborted.", parse_mode="Markdown")
    if tool_call:
        await db.log_audit(
            command=f"{tool_call.tool_name} {tool_call.args}",
            tier=2,
            status="CANCELLED",
            details="User pressed Cancel button",
        )


@router.callback_query(F.data.startswith("page:"))
async def handle_pagination_callback(callback: CallbackQuery) -> None:
    """Handle pagination navigation (Prev/Next) for directory file listings."""
    if is_system_locked():
        await callback.answer("System is locked.", show_alert=True)
        return

    try:
        parts = callback.data.split(":")
        if len(parts) != 3:
            await callback.answer()
            return
        _, session_id, page_str = parts
        page = int(page_str)

        new_keyboard = build_dir_keyboard(session_id, page=page)
        if not new_keyboard:
            await callback.answer("Directory session expired or unavailable.", show_alert=True)
            return

        if callback.message:
            await callback.message.edit_reply_markup(reply_markup=new_keyboard)
        await callback.answer()
    except Exception as e:
        logger.error("Error in handle_pagination_callback: %s", e)
        await callback.answer("Could not change page.", show_alert=True)


@router.callback_query(F.data == "ignore")
async def handle_ignore_callback(callback: CallbackQuery) -> None:
    """Acknowledge dummy pagination counter clicks."""
    await callback.answer()


@router.callback_query(F.data.startswith("zipdir:"))
async def handle_zipdir_callback(callback: CallbackQuery, bot: Bot) -> None:
    """Bundle and deliver entire directory as zip archive."""
    if is_system_locked():
        await callback.answer("System is locked.", show_alert=True)
        return

    try:
        parts = callback.data.split(":", 1)
        if len(parts) != 2:
            await callback.answer()
            return
        session_id = parts[1]
        sess = ACTIVE_DIR_SESSIONS.get(session_id)
        if not sess:
            await callback.answer("Directory session expired or unavailable.", show_alert=True)
            return

        dir_path_str = sess.get("dir_path", "")
        dir_path = Path(dir_path_str).resolve()

        # Security Invariant: Directory Jail validation
        if not sandbox.is_path_allowed(dir_path) or not dir_path.is_dir():
            await callback.answer("Access denied: Directory is outside allowed folders or does not exist.", show_alert=True)
            return

        await callback.answer("Bundling directory as zip...")
        chat_id = callback.message.chat.id if callback.message else callback.from_user.id
        await system_tools.deliver_path(str(dir_path), bot=bot, chat_id=chat_id)
        await db.log_audit(command=f"zipdir {dir_path.name}", tier=1, status="SUCCESS", details=str(dir_path))
    except Exception as e:
        logger.error("Error in handle_zipdir_callback: %s", e)
        await callback.answer("Error bundling directory.", show_alert=True)


@router.callback_query(F.data.startswith("sendfile:"))
async def handle_sendfile_callback(callback: CallbackQuery, bot: Bot) -> None:
    """Send file directly upon user clicking an inline download button."""
    if is_system_locked():
        await callback.answer("System is locked.", show_alert=True)
        return

    try:
        parts = callback.data.split(":")
        file_path_str: Optional[str] = None

        if len(parts) == 3:
            # Format: sendfile:{session_id}:{file_index}
            session_id = parts[1]
            file_idx_str = parts[2]
            sess = ACTIVE_DIR_SESSIONS.get(session_id)
            if sess and file_idx_str.isdigit():
                dir_path = Path(sess.get("dir_path", ""))
                files = sess.get("files", [])
                idx = int(file_idx_str)
                if 0 <= idx < len(files):
                    file_path_str = str((dir_path / files[idx]).resolve())
        elif len(parts) == 2:
            raw_key = parts[1]
            file_path_str = ACTIVE_FILE_BUTTONS.get(raw_key)
            if not file_path_str and raw_key.isdigit():
                idx = int(raw_key)
                matches = LAST_SEARCH_RESULTS.get(callback.from_user.id, [])
                if 0 <= idx < len(matches):
                    file_path_str = matches[idx]["path"]

        if not file_path_str:
            await callback.answer("File is no longer available or was moved.", show_alert=True)
            return

        file_path = Path(file_path_str).resolve()

        # Security Invariant: Directory Jail validation
        if not sandbox.is_path_allowed(file_path) or not file_path.is_file():
            await callback.answer("Access denied: File is outside allowed directories or does not exist.", show_alert=True)
            return

        await callback.answer("Sending file...")
        doc = FSInputFile(str(file_path))
        size_str = system_tools._format_size(file_path.stat().st_size)
        chat_id = callback.message.chat.id if callback.message else callback.from_user.id
        await bot.send_document(
            chat_id,
            doc,
            caption=f"📄 Delivered: `{file_path.name}` ({size_str})",
            parse_mode="Markdown",
        )
        await db.log_audit(command=f"deliver_path {file_path.name}", tier=1, status="SUCCESS", details=str(file_path))
        return

    except Exception as e:
        logger.error("Error in handle_sendfile_callback: %s", e)
        await callback.answer("File is no longer available or was moved.", show_alert=True)


# =====================================================================
# Main Message Processing Pipeline
# =====================================================================


@router.message(F.text)
async def handle_text_message(message: Message, bot: Bot) -> None:
    """Process incoming user text commands through fast_router and permission gate."""
    user_id = message.from_user.id
    raw_text = (message.text or "").strip()

    # 1. System Lock Guard
    if is_system_locked():
        PENDING_COMMAND_QUEUE.pop(user_id, None)
        await message.answer(
            "🚨 *SYSTEM IS LOCKED*\n\n"
            "Remote commands are disabled following an emergency stop.\n"
            "Unlock locally or send `/unlock <PIN>`.",
            parse_mode="Markdown",
        )
        return

    # 2. Check for active Tier 3 PIN verification
    if user_id in PENDING_PIN_ACTIONS:
        pin_match = re.match(r"^YES\s+(\S+)$", raw_text, re.IGNORECASE)
        if pin_match:
            # IMMEDIATELY delete the user's PIN message so it never stays in chat history
            try:
                await bot.delete_message(chat_id=message.chat.id, message_id=message.message_id)
            except Exception as e:
                logger.warning("Could not delete PIN message: %s", e)

            provided_pin = pin_match.group(1).strip()
            settings = get_settings()
            tool_call = PENDING_PIN_ACTIONS.pop(user_id)

            if provided_pin == settings.SAFETY_PIN:
                await message.answer(
                    f"🔓 *PIN Verified.* Executing `{tool_call.tool_name}`...",
                    parse_mode="Markdown",
                )
                # If this was part of an AI Planner session, resume planning without double output
                if user_id in PENDING_PLANNER_SESSIONS:
                    planner, paused_state = PENDING_PLANNER_SESSIONS.pop(user_id)
                    tool_out = await execute_tool_locally(tool_call.tool_name, tool_call.args)
                    await db.log_audit(
                        command=f"{tool_call.tool_name} {tool_call.args}",
                        tier=3,
                        status="SUCCESS",
                    )
                    resumed_res = await planner.resume_after_approval(paused_state, tool_out)

                    # Task 3.1: Render intermediate message if present
                    if getattr(resumed_res, "intermediate_message", None):
                        await message.answer(resumed_res.intermediate_message)

                    # Task 3.1: Check if planner paused on subsequent Tier 2 or Tier 3 tool call
                    if resumed_res.paused_for_approval:
                        await render_planner_approval_prompt(
                            bot=bot,
                            chat_id=message.chat.id,
                            user_id=user_id,
                            planner=planner,
                            planner_res=resumed_res,
                            message=message,
                        )
                        return

                    # Task 3.1: Only if not paused and final_message
                    if not resumed_res.paused_for_approval and resumed_res.final_message:
                        await message.answer(resumed_res.final_message)
                    await process_next_in_queue(message, user_id, bot=bot)
                else:
                    await execute_tool_call(tool_call, bot, message.chat.id)
                    await process_next_in_queue(message, user_id, bot=bot)
            else:
                PENDING_COMMAND_QUEUE.pop(user_id, None)
                await message.answer("❌ *Incorrect PIN.* Action aborted.", parse_mode="Markdown")
                await db.log_audit(
                    command=f"{tool_call.tool_name} {tool_call.args}",
                    tier=3,
                    status="BLOCKED",
                    details="Invalid safety PIN provided",
                )
            return
        elif raw_text.lower() in ("cancel", "abort", "no"):
            PENDING_PIN_ACTIONS.pop(user_id, None)
            PENDING_COMMAND_QUEUE.pop(user_id, None)
            await message.answer("❌ Action cancelled.")
            return

    # 3. Normal command arrival: split compound command & initialize queue
    commands = split_compound_command(raw_text)
    if not commands:
        return
    PENDING_COMMAND_QUEUE[user_id] = commands[1:]
    await execute_single_user_command(message, user_id, commands[0], bot=bot)


def setup_dispatcher(bot: Bot) -> Any:
    """Create and configure aiogram Dispatcher with OwnerOnlyMiddleware."""
    from aiogram import Dispatcher
    dp = Dispatcher()

    owner_id = get_settings().OWNER_TELEGRAM_ID
    # Register Owner-Only Lock middleware on both message and callback_query
    dp.message.outer_middleware(OwnerOnlyMiddleware(owner_id))
    dp.callback_query.outer_middleware(OwnerOnlyMiddleware(owner_id))

    # Include gateway router
    dp.include_router(router)
    return dp
