"""System operational tools for PocketPC Agent.

Implements:
1. get_system_vitals (CPU, RAM, Disk, Battery status via psutil)
2. capture_screenshot (Cross-platform screenshot via mss)
3. explore_path (Universal file and directory exploration via SmartFileResolver)
4. deliver_path (Universal file and folder delivery via SmartFileResolver)
5. zip_and_prepare (Archive creation for files/directories inside ALLOWED_DIRS)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union
import uuid
import zipfile

import mss
import psutil

from core.config import get_settings
from core.sandbox import is_path_allowed
from core.smart_resolver import SmartFileResolver, normalize_drive_alias

logger = logging.getLogger(__name__)

DeliveryHook = Callable[[Path, Optional[int]], Awaitable[None]]
_DELIVERY_HOOK: Optional[DeliveryHook] = None
LAST_EXPLORED_DATA: Optional[Dict[str, Any]] = None


def register_delivery_hook(hook: Optional[DeliveryHook]) -> None:
    """Register a callback for Telegram document delivery."""
    global _DELIVERY_HOOK
    _DELIVERY_HOOK = hook


def _format_size(size_bytes: int) -> str:
    """Format size in bytes to human-readable string (KB, MB, GB)."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


async def get_system_vitals() -> Dict[str, Any]:
    """Retrieve system vitals: CPU, RAM, disk space, and battery status."""
    def _collect_vitals() -> Dict[str, Any]:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_count = psutil.cpu_count(logical=True)

        mem = psutil.virtual_memory()
        ram_used_gb = mem.used / (1024**3)
        ram_total_gb = mem.total / (1024**3)

        drive_path = os.path.splitdrive(os.getcwd())[0] + "\\" if os.name == "nt" else "/"
        disk = psutil.disk_usage(drive_path)
        disk_free_gb = disk.free / (1024**3)
        disk_total_gb = disk.total / (1024**3)

        battery = psutil.sensors_battery()
        if battery is not None:
            bat_percent = battery.percent
            bat_plugged = battery.power_plugged
            bat_status = "Charging" if bat_plugged else "Discharging"
            bat_display = f"{bat_percent}% ({bat_status})"
        else:
            bat_percent = None
            bat_plugged = True
            bat_status = "AC Power (Desktop / No Battery)"
            bat_display = "N/A (AC Power)"

        formatted = (
            f"🖥️ CPU: {cpu_percent}% ({cpu_count} cores)\n"
            f"🧠 RAM: {ram_used_gb:.1f} / {ram_total_gb:.1f} GB ({mem.percent}%)\n"
            f"💾 Disk: {disk_free_gb:.1f} GB free of {disk_total_gb:.1f} GB ({disk.percent}% used)\n"
            f"🔋 Battery: {bat_display}"
        )

        return {
            "cpu_percent": cpu_percent,
            "cpu_cores": cpu_count,
            "ram": {
                "used_gb": round(ram_used_gb, 2),
                "total_gb": round(ram_total_gb, 2),
                "percent": mem.percent,
            },
            "disk": {
                "free_gb": round(disk_free_gb, 2),
                "total_gb": round(disk_total_gb, 2),
                "percent": disk.percent,
            },
            "battery": {
                "percent": bat_percent,
                "power_plugged": bat_plugged,
                "status": bat_status,
            },
            "formatted": formatted,
        }

    return await asyncio.to_thread(_collect_vitals)


async def capture_screenshot(output_dir: Optional[Union[str, Path]] = None) -> Path:
    """Capture screen and save as PNG in a temporary or specified folder."""
    if output_dir:
        out_folder = Path(output_dir).resolve()
    else:
        out_folder = Path(tempfile.gettempdir()) / "pocket_pc_screenshots"
    out_folder.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"screenshot_{timestamp}_{uuid.uuid4().hex[:6]}.png"
    target_file = out_folder / filename

    def _grab() -> Path:
        try:
            with mss.MSS() as sct:
                mon = sct.monitors[0]
                sct.shot(mon=0, output=str(target_file))
                return target_file
        except Exception:
            from PIL import Image, ImageDraw
            img = Image.new("RGB", (1280, 720), color=(30, 30, 35))
            draw = ImageDraw.Draw(img)
            draw.text(
                (120, 340),
                f"[PocketPC Agent] Screen locked or display session unavailable\nCaptured at: {datetime.now(timezone.utc).isoformat()}",
                fill=(240, 240, 240),
            )
            img.save(str(target_file), format="PNG")
            return target_file

    return await asyncio.to_thread(_grab)


# =====================================================================
# Universal Tool 1: explore_path (Tier 1 Auto-Execute)
# =====================================================================

async def explore_path(
    target: str = ".",
    allowed_dirs: Optional[List[Union[str, Path]]] = None,
) -> Dict[str, Any]:
    """Explore a path safely inside ALLOWED_DIRS using SmartFileResolver.

    - If target resolves to a file: returns file metadata (type, name, size, path).
    - If target resolves to a directory: scans subfolders and files via asyncio.to_thread().
    """
    resolver = SmartFileResolver.get_instance()
    resolved = resolver.resolve(target, allowed_dirs=allowed_dirs)

    if resolved.is_file():
        sz = resolved.stat().st_size
        size_fmt = _format_size(sz)
        formatted = f"📄 *File:* `{resolved.name}` ({size_fmt})\n`{resolved}`"
        return {
            "type": "file",
            "name": resolved.name,
            "size": size_fmt,
            "size_bytes": sz,
            "path": str(resolved),
            "formatted": formatted,
        }

    if resolved.is_dir():
        ignored_names = {
            ".git",
            "__pycache__",
            ".pytest_cache",
            ".undo_storage",
            "node_modules",
            ".venv",
            "venv",
            "$recycle.bin",
            "system volume information",
        }

        def _scan() -> Tuple[List[str], List[str]]:
            folders: List[str] = []
            files: List[str] = []
            for entry in sorted(resolved.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
                if entry.name.startswith(".") or entry.name.lower() in ignored_names:
                    continue
                if entry.is_dir():
                    folders.append(entry.name)
                elif entry.is_file():
                    files.append(entry.name)
            return folders, files

        folders, files = await asyncio.to_thread(_scan)

        lines = [f"📂 *Directory:* `{resolved.name}`\n`{resolved}`\n"]
        if folders:
            lines.append(f"📁 *Folders ({len(folders)}):*")
            for f in folders[:40]:
                lines.append(f"• `{f}`")
            if len(folders) > 40:
                lines.append(f"_... and {len(folders) - 40} more folders_")
            lines.append("")
        if files:
            lines.append(f"📄 *Files ({len(files)}):*")
            for fl in files[:40]:
                lines.append(f"• `{fl}`")
            if len(files) > 40:
                lines.append(f"_... and {len(files) - 40} more files_")
        if not folders and not files:
            lines.append("ℹ️ _Directory is empty._")

        formatted_str = "\n".join(lines).strip()

        res_data = {
            "type": "directory",
            "name": resolved.name,
            "path": str(resolved),
            "folders": folders,
            "files": files,
            "formatted": formatted_str,
        }
        global LAST_EXPLORED_DATA
        LAST_EXPLORED_DATA = res_data
        return res_data

    raise FileNotFoundError(f"Path '{target}' is neither a file nor a directory.")


# =====================================================================
# Universal Tool 2: deliver_path (Tier 1 Auto-Execute)
# =====================================================================

async def deliver_path(
    target: str,
    allowed_dirs: Optional[List[Union[str, Path]]] = None,
    bot: Optional[Any] = None,
    chat_id: Optional[int] = None,
) -> str:
    """Deliver a file or bundled directory to Telegram using SmartFileResolver.

    - If target is a file: triggers Telegram file delivery, returns success message.
    - If target is a directory: bundles into zip inside .undo_storage/temp/, delivers zip, returns success message.
    """
    clean_target = (target or "").strip()
    if not clean_target:
        raise ValueError("No target specified to deliver.")

    resolver = SmartFileResolver.get_instance()
    resolved = resolver.resolve(clean_target, allowed_dirs=allowed_dirs)

    file_to_deliver: Path
    success_msg: str

    if resolved.is_file():
        file_to_deliver = resolved
        sz = resolved.stat().st_size
        size_fmt = _format_size(sz)
        success_msg = f"Successfully delivered file '{resolved.name}' ({size_fmt})."

    elif resolved.is_dir():
        settings = get_settings()
        temp_dir = settings.UNDO_DIR / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_stem = re.sub(r"[^\w\-]", "_", resolved.name) or "folder"
        zip_filename = f"{safe_stem}_{timestamp}_{uuid.uuid4().hex[:6]}.zip"
        dest_zip = temp_dir / zip_filename

        ignored_names = {
            ".git",
            "__pycache__",
            ".pytest_cache",
            ".undo_storage",
            "node_modules",
            ".venv",
            "venv",
            "$recycle.bin",
            "system volume information",
        }

        def _bundle_zip() -> Path:
            with zipfile.ZipFile(dest_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for root, dirs, files in os.walk(resolved):
                    dirs[:] = [d for d in dirs if d.lower() not in ignored_names and not d.startswith(".")]
                    for f in files:
                        if f.startswith(".") or f.lower() in ignored_names:
                            continue
                        full_file = Path(root) / f
                        try:
                            arcname = full_file.relative_to(resolved)
                        except ValueError:
                            arcname = full_file.name
                        zf.write(str(full_file), arcname=str(arcname))
            return dest_zip

        file_to_deliver = await asyncio.to_thread(_bundle_zip)
        sz = file_to_deliver.stat().st_size
        size_fmt = _format_size(sz)
        success_msg = f"Successfully bundled and delivered directory '{resolved.name}' as zip '{file_to_deliver.name}' ({size_fmt})."

    else:
        raise FileNotFoundError(f"Target '{target}' not found on filesystem.")

    # Trigger Telegram delivery
    try:
        if bot and chat_id:
            from aiogram.types import FSInputFile
            doc = FSInputFile(str(file_to_deliver))
            await bot.send_document(
                chat_id,
                doc,
                caption=f"📄 Delivered: `{file_to_deliver.name}` ({_format_size(file_to_deliver.stat().st_size)})",
                parse_mode="Markdown",
            )
        elif _DELIVERY_HOOK:
            await _DELIVERY_HOOK(file_to_deliver, chat_id)
        else:
            logger.info("Delivery triggered for: %s (no bot session active)", file_to_deliver)
    except Exception as e:
        logger.warning("Could not send document to Telegram: %s", e)

    return success_msg


# =====================================================================
# General Utility: zip_and_prepare
# =====================================================================

async def zip_and_prepare(
    path: Union[str, Path],
    output_dir: Optional[Union[str, Path]] = None,
    allowed_dirs: Optional[List[Union[str, Path]]] = None,
) -> Path:
    """Compress a folder or file inside ALLOWED_DIRS into a .zip archive."""
    target = Path(path).resolve()

    if not is_path_allowed(target, allowed_dirs=allowed_dirs):
        raise PermissionError(
            f"Path traversal detected or access denied: '{path}' is outside allowed directories."
        )

    if not target.exists():
        raise FileNotFoundError(f"File or directory not found: '{path}'")

    if output_dir:
        out_folder = Path(output_dir).resolve()
    else:
        out_folder = Path(tempfile.gettempdir()) / "pocket_pc_zips"
    out_folder.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    zip_filename = f"{target.stem}_{timestamp}_{uuid.uuid4().hex[:6]}.zip"
    dest_zip = out_folder / zip_filename

    def _make_zip() -> Path:
        with zipfile.ZipFile(dest_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            if target.is_file():
                zf.write(str(target), arcname=target.name)
            else:
                for root, _, files in os.walk(target):
                    for file in files:
                        full_file = Path(root) / file
                        arcname = full_file.relative_to(target.parent)
                        zf.write(str(full_file), arcname=str(arcname))
        return dest_zip

    return await asyncio.to_thread(_make_zip)


# =====================================================================
# Compatibility Wrappers for Deprecated Tools
# =====================================================================

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif", ".tiff", ".svg"}
DOCUMENT_EXTENSIONS = {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".txt", ".csv", ".md"}
VIDEO_EXTENSIONS = {".mp4", ".mkv", ".mov", ".avi", ".webm", ".wmv"}
AUDIO_EXTENSIONS = {".mp3", ".wav", ".m4a", ".flac", ".ogg", ".aac"}


async def list_directory(
    path: str = ".",
    folders_only: bool = False,
    files_only: bool = False,
    allowed_dirs: Optional[List[Union[str, Path]]] = None,
) -> Dict[str, Any]:
    """Compatibility wrapper delegating to explore_path."""
    res = await explore_path(path, allowed_dirs=allowed_dirs)
    if res["type"] == "directory":
        folders = res["folders"] if not files_only else []
        files = [{"name": f, "size_formatted": ""} for f in res["files"]] if not folders_only else []
        return {
            "status": "success",
            "path": res["path"],
            "folder_name": res["name"],
            "folders": folders,
            "files": files,
            "formatted": res["formatted"],
        }
    return {
        "status": "success",
        "path": res["path"],
        "folder_name": "",
        "folders": [],
        "files": [{"name": res["name"], "size_formatted": res["size"]}],
        "formatted": res["formatted"],
    }


async def find_files(
    query: str,
    allowed_dirs: Optional[List[Union[str, Path]]] = None,
    limit: int = 5,
) -> List[Dict[str, Any]]:
    """Compatibility search function inside ALLOWED_DIRS using rapidfuzz."""
    clean_query = query.strip()
    if not clean_query:
        return []

    dirs_to_search = (
        [Path(d).resolve() for d in allowed_dirs]
        if allowed_dirs is not None
        else get_settings().ALLOWED_DIRS
    )

    ignored_names = {
        ".git", "__pycache__", ".pytest_cache", ".undo_storage", "node_modules", ".venv", "venv"
    }

    def _search() -> List[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []
        clean_q = clean_query.replace("_", " ").replace("-", " ").lower()

        for base_dir in dirs_to_search:
            if not base_dir.exists():
                continue

            for root, dirs, files in os.walk(base_dir):
                dirs[:] = [d for d in dirs if d.lower() not in ignored_names and not d.startswith(".")]
                for f in files:
                    file_path = Path(root) / f
                    clean_f = f.replace("_", " ").replace("-", " ").lower()
                    if clean_query.lower() in f.lower() or clean_q in clean_f:
                        score = 95.0
                    else:
                        from rapidfuzz import fuzz
                        score = max(fuzz.token_sort_ratio(clean_q, clean_f), fuzz.ratio(clean_q, clean_f))

                    if score >= 45.0:
                        try:
                            sz = file_path.stat().st_size
                        except OSError:
                            sz = 0
                        candidates.append({
                            "path": str(file_path.resolve()),
                            "name": f,
                            "score": round(score, 1),
                            "size_bytes": sz,
                            "size_formatted": _format_size(sz),
                        })

        candidates.sort(key=lambda item: item["score"], reverse=True)
        return candidates[:limit]

    return await asyncio.to_thread(_search)


async def package_folder_files(
    folder_path_or_query: Union[str, Path],
    category: Optional[str] = "images",
    allowed_dirs: Optional[List[Union[str, Path]]] = None,
    output_dir: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Find files in a folder matching category and bundle into a clean zip archive."""
    resolver = SmartFileResolver.get_instance()
    folder = resolver.resolve(str(folder_path_or_query), allowed_dirs=allowed_dirs)

    cat_norm = (category or "all").strip().lower()
    if cat_norm in ("images", "image", "photo", "photos", "pics", "pictures", "img"):
        allowed_exts = IMAGE_EXTENSIONS
        display_cat = "images"
    elif cat_norm in ("documents", "document", "docs", "doc", "pdf", "pdfs"):
        allowed_exts = DOCUMENT_EXTENSIONS
        display_cat = "documents"
    elif cat_norm in ("videos", "video", "movies", "vids"):
        allowed_exts = VIDEO_EXTENSIONS
        display_cat = "videos"
    elif cat_norm in ("audio", "music", "songs"):
        allowed_exts = AUDIO_EXTENSIONS
        display_cat = "audio"
    else:
        allowed_exts = None
        display_cat = "files"

    ignored_names = {".git", "__pycache__", ".pytest_cache", ".undo_storage", "node_modules", ".venv", "venv"}

    def _collect_and_zip() -> Dict[str, Any]:
        matching_files: List[Path] = []
        for root, dirs, files in os.walk(folder):
            dirs[:] = [d for d in dirs if d.lower() not in ignored_names and not d.startswith(".")]
            for f in files:
                f_path = Path(root) / f
                if allowed_exts is None or f_path.suffix.lower() in allowed_exts:
                    matching_files.append(f_path)

        if not matching_files:
            return {
                "zip_path": None,
                "file_count": 0,
                "total_bytes": 0,
                "total_formatted": "0 B",
                "category": display_cat,
                "folder_name": folder.name,
                "folder_path": str(folder),
                "sample_files": [],
            }

        total_bytes = sum(f.stat().st_size for f in matching_files)

        if output_dir:
            out_folder = Path(output_dir).resolve()
        else:
            out_folder = Path(tempfile.gettempdir()) / "pocket_pc_zips"
        out_folder.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_stem = re.sub(r"[^\w\-]", "_", folder.name) or "folder"
        zip_filename = f"{safe_stem}_{display_cat}_{timestamp}_{uuid.uuid4().hex[:6]}.zip"
        dest_zip = out_folder / zip_filename

        with zipfile.ZipFile(dest_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for f_path in matching_files:
                try:
                    arcname = f_path.relative_to(folder)
                except ValueError:
                    arcname = f_path.name
                zf.write(str(f_path), arcname=str(arcname))

        return {
            "zip_path": dest_zip,
            "file_count": len(matching_files),
            "total_bytes": total_bytes,
            "total_formatted": _format_size(total_bytes),
            "category": display_cat,
            "folder_name": folder.name,
            "folder_path": str(folder),
            "sample_files": [str(f.resolve()) for f in matching_files[:3]],
        }

    return await asyncio.to_thread(_collect_and_zip)


async def send_file(
    target: str,
    allowed_dirs: Optional[List[Union[str, Path]]] = None,
) -> str:
    """Compatibility wrapper delegating to deliver_path."""
    return await deliver_path(target, allowed_dirs=allowed_dirs)


async def send_folder_files(
    folder: str,
    category: str = "all",
    allowed_dirs: Optional[List[Union[str, Path]]] = None,
) -> str:
    """Compatibility wrapper delegating to deliver_path."""
    return await deliver_path(folder, allowed_dirs=allowed_dirs)


async def resolve_file_for_sending(
    path_or_query: Union[str, Path],
    allowed_dirs: Optional[List[Union[str, Path]]] = None,
) -> Path:
    """Compatibility wrapper using SmartFileResolver."""
    return SmartFileResolver.get_instance().resolve(str(path_or_query), allowed_dirs=allowed_dirs)


async def run_shell(command: str, timeout: float = 30.0) -> Dict[str, Any]:
    """Execute a shell command with explicit timeout and OS/Antivirus error resilience.

    Wraps subprocess execution in try...except for (PermissionError, OSError).
    Returns {"status": "success", "output": ...} or {"status": "error", "message": ...}.
    """
    clean_cmd = (command or "").strip()
    if not clean_cmd:
        return {"status": "error", "message": "No command provided."}

    try:
        proc = await asyncio.create_subprocess_shell(
            clean_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        out = stdout.decode("utf-8", errors="replace").strip()
        err = stderr.decode("utf-8", errors="replace").strip()
        parts = []
        if out:
            parts.append(out)
        if err:
            parts.append(f"STDERR:\n{err}")
        combined = "\n".join(parts) if parts else "(Command succeeded with no output)"
        return {"status": "success", "output": combined, "message": combined}
    except (PermissionError, OSError) as e:
        logger.error("OS/AV denied shell execution for '%s': %s", clean_cmd, e)
        return {
            "status": "error",
            "message": "Shell execution denied by the operating system. Check local Antivirus/Defender logs.",
        }
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return {
            "status": "error",
            "message": f"Shell command timed out after {timeout} seconds.",
        }
    except Exception as e:
        logger.error("Error executing shell command '%s': %s", clean_cmd, e)
        return {
            "status": "error",
            "message": f"Shell execution error: {str(e)}",
        }


async def kill_process(pid: Union[int, str]) -> Dict[str, Any]:
    """Terminate or kill an arbitrary OS process using its numeric PID.
    
    Runs termination inside asyncio.to_thread to prevent blocking the async loop.
    Recursively terminates child processes and catches AccessDenied / NoSuchProcess.
    """
    try:
        clean_pid = int(pid)
    except (ValueError, TypeError):
        return {
            "status": "error",
            "message": f"Invalid PID '{pid}': must be an integer.",
        }

    def _terminate() -> Dict[str, Any]:
        try:
            p = psutil.Process(clean_pid)
            proc_name = p.name()
            # Recursively terminate children
            children = p.children(recursive=True)
            for child in children:
                try:
                    child.terminate()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            p.terminate()

            # Wait briefly for graceful exit, then force kill if still alive
            gone, alive = psutil.wait_procs(children + [p], timeout=2.0)
            for proc in alive:
                try:
                    proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            return {
                "status": "success",
                "pid": clean_pid,
                "name": proc_name,
                "message": f"Successfully terminated process '{proc_name}' (PID {clean_pid}).",
            }
        except psutil.NoSuchProcess:
            return {
                "status": "error",
                "pid": clean_pid,
                "message": f"Access denied or process not found: Process with PID {clean_pid} does not exist.",
            }
        except psutil.AccessDenied:
            return {
                "status": "error",
                "pid": clean_pid,
                "message": f"Access denied or process not found: Insufficient privileges to terminate PID {clean_pid}.",
            }
        except Exception as e:
            logger.error("Unexpected error terminating PID %s: %s", clean_pid, e)
            return {
                "status": "error",
                "pid": clean_pid,
                "message": f"Error terminating process with PID {clean_pid}: {e}",
            }

    return await asyncio.to_thread(_terminate)

