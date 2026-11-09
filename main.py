"""Main entry point for PocketPC Agent daemon.

Initializes:
1. Configuration and logging.
2. Async SQLite audit & state database.
3. Sandbox directory with sample test_resume.pdf.
4. aiogram v3 Telegram bot with OwnerOnlyMiddleware.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
import sys

from aiogram import Bot
from aiogram.enums import ParseMode

from bot.telegram_gateway import setup_dispatcher
from core.config import get_settings
from core import db
from core import keep_awake
from core.smart_resolver import SmartFileResolver
from tools.dev_services import load_services_registry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("pocket_pc_agent")


def ensure_sandbox_fixtures() -> Path:
    """Ensure sandbox directory exists and contains sample test_resume.pdf."""
    settings = get_settings()
    sandbox_dir = settings.ALLOWED_DIRS[0]
    sandbox_dir.mkdir(parents=True, exist_ok=True)

    sample_resume = sandbox_dir / "test_resume.pdf"
    if not sample_resume.exists():
        # Minimal valid PDF file fixture
        pdf_bytes = (
            b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
            b"xref\n0 4\n0000000000 65535 f\n0000000010 00000 n\n0000000060 00000 n\n0000000117 00000 n\n"
            b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n185\n%%EOF\n"
        )
        sample_resume.write_bytes(pdf_bytes)
        logger.info("Created sample test fixture: %s", sample_resume)

    return sandbox_dir


async def main() -> None:
    """Initialize database, fixtures, and start Telegram bot polling."""
    settings = get_settings()
    logger.info("Starting PocketPC Agent Daemon...")
    logger.info("Owner Telegram ID: %s", settings.OWNER_TELEGRAM_ID)
    logger.info("Allowed Dirs: %s", settings.ALLOWED_DIRS)
    logger.info("Undo Storage: %s", settings.UNDO_DIR)

    # 1. Initialize SQLite Database
    await db.init_db()
    logger.info("Database initialized at: %s", settings.DATABASE_PATH)

    # 2. Ensure sandbox fixtures
    sandbox_dir = ensure_sandbox_fixtures()
    logger.info("Sandbox directory verified: %s", sandbox_dir)

    # 3. Ensure services.json registry exists
    load_services_registry()
    logger.info("Developer services registry loaded.")

    # 4. Enable Windows sleep prevention (Caffeinate)
    keep_awake.enable_keep_awake()
    logger.info("Host sleep prevention enabled.")

    # 5. Build SmartFileResolver index asynchronously without blocking main event loop
    resolver = SmartFileResolver.get_instance()
    await resolver.build_index()
    logger.info("SmartFileResolver directory index built.")

    # 6. Check Telegram Bot Token
    if not settings.TELEGRAM_BOT_TOKEN or "your_bot_token" in settings.TELEGRAM_BOT_TOKEN:
        logger.error(
            "TELEGRAM_BOT_TOKEN is not configured in .env! "
            "Please configure OWNER_TELEGRAM_ID and TELEGRAM_BOT_TOKEN."
        )
        return

    # 6. Initialize Bot & Dispatcher
    bot = Bot(token=settings.TELEGRAM_BOT_TOKEN)
    dp = setup_dispatcher(bot)

    logger.info("Starting aiogram v3 long-polling gateway...")
    try:
        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
    finally:
        keep_awake.disable_keep_awake()
        await bot.session.close()
        logger.info("PocketPC Agent shut down cleanly.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Daemon terminated by user.")
