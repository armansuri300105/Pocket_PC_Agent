"""Surveillance and anti-theft security tools for PocketPC Agent.

Implements:
1. capture_webcam_photo: Silently captures a webcam photo using OpenCV (cv2).
2. capture_multi_screenshots: Captures multiple screenshots across open OS windows.
3. get_location_telemetry: Gathers public IP geolocation and nearby Wi-Fi BSSIDs via netsh.
4. lock_workstation: Immediately locks the Windows session and wipes the clipboard.
"""

from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Set, Union
import urllib.request
import uuid

from core.config import get_settings

logger = logging.getLogger(__name__)

LAST_WEBCAM_PATH: Optional[Path] = None
LAST_MULTI_SCREENSHOT_PATHS: List[str] = []
WINDOW_REGISTRY: List[Dict[str, Any]] = []

DENYLIST: Set[str] = {
    "nahimic",
    "program manager",
    "windows input experience",
    "textinputhost",
    "microsoft text input application",
    "nvidia geforce overlay",
    "settings",
    "systemsettings",
    "gamebar",
    "widgets",
    "searchhost",
}


class AwaitableDict(dict):
    """Dictionary that can be directly awaited in async contexts or used as a standard dict."""

    def __await__(self):
        async def _coro():
            return self

        return _coro().__await__()


def capture_webcam_photo(camera_index: int = 0) -> dict:
    """Silently capture a photo from the webcam using OpenCV.

    - Uses cv2.CAP_DSHOW on Windows for fast initialization without MSMF delay.
    - Discards 12 warm-up frames to allow auto-exposure to adjust.
    - Releases camera device immediately after capture.
    - Saves photo into .undo_storage/webcam_snap.jpg.
    """
    try:
        import cv2
    except ImportError:
        logger.warning("OpenCV (cv2) is not installed.")
        return AwaitableDict({
            "status": "error",
            "message": "OpenCV (cv2) is not installed.",
        })

    cap = None
    try:
        # Open camera (use CAP_DSHOW on Windows for fast startup)
        if sys.platform.startswith("win") and hasattr(cv2, "CAP_DSHOW"):
            cap = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)
        else:
            cap = cv2.VideoCapture(camera_index)

        if not cap.isOpened():
            return AwaitableDict({
                "status": "error",
                "message": f"Could not access webcam at index {camera_index}.",
            })

        # Discard 12 warm-up frames for auto-exposure adjustment
        for _ in range(12):
            cap.read()

        # Capture final frame
        ret, frame = cap.read()
        cap.release()
        cap = None

        if not ret or frame is None:
            return AwaitableDict({
                "status": "error",
                "message": "Failed to capture frame from webcam.",
            })

        # Save to .undo_storage/webcam_snap.jpg
        settings = get_settings()
        undo_dir = settings.UNDO_DIR
        undo_dir.mkdir(parents=True, exist_ok=True)
        target_path = undo_dir / "webcam_snap.jpg"

        cv2.imwrite(str(target_path), frame)

        global LAST_WEBCAM_PATH
        LAST_WEBCAM_PATH = target_path

        return AwaitableDict({
            "status": "success",
            "image_path": str(target_path),
            "message": "📷 Webcam snapshot captured.",
        })
    except Exception as e:
        logger.error("Error capturing webcam photo: %s", e)
        return AwaitableDict({
            "status": "error",
            "message": f"Webcam capture failed: {str(e)}",
        })
    finally:
        if cap is not None:
            try:
                cap.release()
            except Exception:
                pass


def refresh_window_registry() -> List[Dict[str, Any]]:
    """Enumerate and filter top-level OS windows into WINDOW_REGISTRY."""
    global WINDOW_REGISTRY
    registry: List[Dict[str, Any]] = []

    if sys.platform != "win32" or not hasattr(ctypes, "windll"):
        # For non-Windows environments or unit tests with pre-populated registry
        return list(WINDOW_REGISTRY)

    try:
        from ctypes import wintypes
        import psutil

        user32 = ctypes.windll.user32
        dwmapi = ctypes.windll.dwmapi

        WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        GetWindowLong = getattr(user32, "GetWindowLongPtrW", user32.GetWindowLongW)

        hdesk = None
        if hasattr(user32, "OpenInputDesktop"):
            try:
                hdesk = user32.OpenInputDesktop(0, False, 0x0100)
            except Exception:
                hdesk = None
        if not hdesk and hasattr(user32, "GetThreadDesktop") and hasattr(ctypes.windll, "kernel32"):
            try:
                hdesk = user32.GetThreadDesktop(ctypes.windll.kernel32.GetCurrentThreadId())
            except Exception:
                hdesk = None

        seen_hwnds: Set[int] = set()

        def enum_cb(hwnd: int, lparam: int) -> bool:
            if hwnd in seen_hwnds:
                return True
            seen_hwnds.add(hwnd)

            # a. Is visible
            if not user32.IsWindowVisible(hwnd):
                return True

            # b. Has non-empty title
            length = user32.GetWindowTextLengthW(hwnd)
            if length == 0:
                return True
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value.strip()
            if not title:
                return True

            # c. WS_EX_TOOLWINDOW check (0x00000080) unless WS_EX_APPWINDOW (0x00040000)
            ex_style = GetWindowLong(hwnd, -20)
            if (ex_style & 0x00000080) and not (ex_style & 0x00040000):
                return True

            # d. Crucial DWM Cloaked check (DWMWA_CLOAKED = 14)
            cloaked = ctypes.c_int(0)
            hr = dwmapi.DwmGetWindowAttribute(hwnd, 14, ctypes.byref(cloaked), ctypes.sizeof(cloaked))
            if hr == 0 and cloaked.value != 0:
                return True

            # Extract PID and executable name
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            exe_name = ""
            if pid.value:
                try:
                    exe_name = psutil.Process(pid.value).name()
                except Exception:
                    exe_name = ""

            app_short = Path(exe_name).stem.lower() if exe_name else ""
            if not app_short:
                app_short = title.split()[-1].lower() if title else "window"

            # e. Background noise denylist
            title_lower = title.lower()
            exe_lower = exe_name.lower()
            app_lower = app_short.lower()
            for denied in DENYLIST:
                if denied in title_lower or denied in exe_lower or denied in app_lower:
                    return True

            is_min = bool(user32.IsIconic(hwnd))

            registry.append({
                "id": len(registry) + 1,
                "hwnd": hwnd,
                "app": app_short,
                "exe": exe_name,
                "title": title,
                "is_minimized": is_min,
            })
            return True

        proc = WNDENUMPROC(enum_cb)
        if hdesk and hasattr(user32, "EnumDesktopWindows"):
            user32.EnumDesktopWindows.argtypes = [wintypes.HDESK, WNDENUMPROC, wintypes.LPARAM]
            user32.EnumDesktopWindows.restype = wintypes.BOOL
            user32.EnumDesktopWindows(hdesk, proc, 0)
        else:
            user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
            user32.EnumWindows.restype = wintypes.BOOL
            user32.EnumWindows(proc, 0)

        WINDOW_REGISTRY = registry
        return registry
    except Exception as e:
        logger.warning("Error refreshing window registry via ctypes: %s", e)
        return list(WINDOW_REGISTRY)


def capture_single_hwnd(entry: dict) -> str:
    """Capture a screenshot of a specific window entry by hwnd, preserving foreground window."""
    settings = get_settings()
    out_dir = settings.UNDO_DIR / "multi_screenshots"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"win_{entry.get('id', 1)}_{entry.get('app', 'window')}.png"

    hwnd = entry.get("hwnd", 0)
    original_hwnd = None

    if sys.platform == "win32" and hasattr(ctypes, "windll"):
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        original_hwnd = user32.GetForegroundWindow() if hasattr(user32, "GetForegroundWindow") else None

        if hwnd and user32.IsWindow(hwnd):
            try:
                if user32.IsIconic(hwnd):
                    user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                user32.SetForegroundWindow(hwnd)
                time.sleep(0.15)
            except Exception as e:
                logger.warning("Could not focus hwnd %s: %s", hwnd, e)

    # Capture screen via mss
    import mss
    with mss.mss() as sct:
        sct.shot(mon=0, output=str(out_path))

    # Crop to bounding box if possible
    if sys.platform == "win32" and hwnd and hasattr(ctypes, "windll"):
        try:
            rect = wintypes.RECT()
            if user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                from PIL import Image
                im = Image.open(out_path)
                w_box = rect.right - rect.left
                h_box = rect.bottom - rect.top
                if w_box > 50 and h_box > 50:
                    crop_box = (
                        max(0, rect.left),
                        max(0, rect.top),
                        min(im.width, max(rect.left + 50, rect.right)),
                        min(im.height, max(rect.top + 50, rect.bottom)),
                    )
                    if crop_box[2] > crop_box[0] and crop_box[3] > crop_box[1]:
                        cropped = im.crop(crop_box)
                        cropped.save(out_path)
        except Exception as e:
            logger.debug("Bounding box crop skipped: %s", e)

        # Restore original foreground window
        try:
            if original_hwnd and user32.IsWindow(original_hwnd):
                user32.SetForegroundWindow(original_hwnd)
        except Exception:
            pass

    return str(out_path)


def capture_window_by_query(query: str) -> dict:
    """Find a window by app name, title, or index in WINDOW_REGISTRY and capture it."""
    global WINDOW_REGISTRY
    if not WINDOW_REGISTRY:
        refresh_window_registry()
    elif sys.platform == "win32" and hasattr(ctypes, "windll"):
        try:
            user32 = ctypes.windll.user32
            valid = [w for w in WINDOW_REGISTRY if user32.IsWindow(w.get("hwnd", 0))]
            if valid:
                WINDOW_REGISTRY = valid
            else:
                new_reg = refresh_window_registry()
                if new_reg and isinstance(new_reg, list):
                    WINDOW_REGISTRY = new_reg
        except Exception:
            pass

    raw_query = (query or "").strip()
    norm_query = re.sub(r"\b(?:tabs?|windows?|the|apps?)\b", "", raw_query, flags=re.IGNORECASE).strip()
    if not norm_query:
        norm_query = raw_query

    matched_entry = None

    # Priority a: digit match
    if norm_query.isdigit():
        target_id = int(norm_query)
        for w in WINDOW_REGISTRY:
            if w.get("id") == target_id:
                matched_entry = w
                break

    # Priority b: common aliases
    if not matched_entry:
        ALIASES = {
            "vscode": ["code"],
            "vs code": ["code"],
            "browser": ["chrome", "msedge", "edge", "brave", "firefox"],
            "terminal": ["powershell", "windowsterminal", "cmd", "bash"],
        }
        target_apps = ALIASES.get(norm_query.lower(), [])
        if target_apps:
            for w in WINDOW_REGISTRY:
                if w.get("app", "").lower() in target_apps:
                    matched_entry = w
                    break

    # Priority c: exact or substring match
    if not matched_entry:
        q_lower = norm_query.lower()
        for w in WINDOW_REGISTRY:
            if w.get("app", "").lower() == q_lower or w.get("exe", "").lower() == q_lower:
                matched_entry = w
                break
        if not matched_entry:
            for w in WINDOW_REGISTRY:
                if (
                    q_lower in w.get("app", "").lower()
                    or q_lower in w.get("exe", "").lower()
                    or q_lower in w.get("title", "").lower()
                ):
                    matched_entry = w
                    break

    # If no match found
    if not matched_entry:
        window_list = "\n".join(
            f"`{w['id']}.` *{w['app']}* — {w['title']}" for w in WINDOW_REGISTRY
        )
        return AwaitableDict({
            "status": "error",
            "message": (
                f"⚠️ No open window matching `{query}` found in active registry.\n\n"
                f"*Currently Open Windows:*\n{window_list}"
                if window_list
                else f"⚠️ No open window matching `{query}` found in active registry (no active windows detected)."
            ),
        })

    # Capture matched window
    path = capture_single_hwnd(matched_entry)
    return AwaitableDict({
        "status": "success",
        "image_path": str(path),
        "message": f"🪟 *Window [{matched_entry['id']}]:* `{matched_entry['app']}`\n{matched_entry['title']}",
    })


def capture_multi_screenshots(mode: str = "windows", count: int = 6) -> dict:
    """Capture multiple screenshots across open taskbar windows."""
    global LAST_MULTI_SCREENSHOT_PATHS
    try:
        count = max(2, min(int(count), 6))
    except (ValueError, TypeError):
        count = 6

    mode = "windows"
    settings = get_settings()
    out_dir = settings.UNDO_DIR / "multi_screenshots"
    out_dir.mkdir(parents=True, exist_ok=True)

    paths: List[str] = []

    # 1. Refresh window registry
    refresh_window_registry()

    target_entries = WINDOW_REGISTRY[:count] if WINDOW_REGISTRY else []

    if target_entries:
        for entry in target_entries:
            path = capture_single_hwnd(entry)
            paths.append(path)

        summary_lines = [f"`{w['id']}.` *{w['app']}* — {w['title']}" for w in target_entries]
        msg = f"🗂️ *Active Window Registry ({len(paths)} open):*\n" + "\n".join(summary_lines)
    else:
        # Fallback to desktop screenshot if no windows detected
        import mss
        with mss.mss() as sct:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            file_path = out_dir / f"desktop_{timestamp}_{uuid.uuid4().hex[:4]}.png"
            sct.shot(mon=0, output=str(file_path))
            paths.append(str(file_path))
        msg = "🖥️ *Captured Desktop Screenshot (no active windows detected).*"

    LAST_MULTI_SCREENSHOT_PATHS = list(paths)

    return AwaitableDict({
        "status": "success",
        "mode": "windows",
        "count": len(paths),
        "image_paths": paths,
        "message": msg,
    })


def get_location_telemetry() -> dict:
    """Gather public IP geolocation and nearby Wi-Fi SSIDs/BSSIDs for physical triangulation.

    - Queries http://ip-api.com/json/ (4s timeout)
    - Executes `netsh wlan show networks mode=bssid` (5s timeout)
    - Returns formatted markdown summary with top 5 Wi-Fi BSSIDs.
    """
    ip_data: Dict[str, Any] = {}
    try:
        req = urllib.request.Request(
            "http://ip-api.com/json/",
            headers={"User-Agent": "PocketPC-Agent/1.0"},
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            ip_data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        logger.warning("Failed to fetch public IP geolocation: %s", e)

    public_ip = ip_data.get("query", "Unavailable")
    isp = ip_data.get("isp", "Unavailable")
    city = ip_data.get("city", "")
    region = ip_data.get("regionName", "")
    country = ip_data.get("country", "")
    lat = ip_data.get("lat")
    lon = ip_data.get("lon")

    loc_str = ", ".join(filter(None, [city, region, country])) or "Unknown"
    coords_str = f"{lat}, {lon}" if lat is not None and lon is not None else "Unknown"

    wifi_networks: List[Dict[str, str]] = []
    if sys.platform.startswith("win"):
        try:
            proc = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            output = proc.stdout or ""
            current_ssid = ""
            for line in output.splitlines():
                line_s = line.strip()
                if line_s.startswith("SSID "):
                    parts = line_s.split(":", 1)
                    if len(parts) == 2:
                        current_ssid = parts[1].strip() or "<Hidden>"
                elif line_s.startswith("BSSID "):
                    parts = line_s.split(":", 1)
                    if len(parts) == 2:
                        current_bssid = parts[1].strip()
                        wifi_networks.append({
                            "ssid": current_ssid or "<Hidden>",
                            "bssid": current_bssid,
                            "signal": "N/A",
                        })
                elif (line_s.startswith("Signal ") or line_s.startswith("Signal:")) and wifi_networks:
                    parts = line_s.split(":", 1)
                    if len(parts) == 2:
                        wifi_networks[-1]["signal"] = parts[1].strip()
        except Exception as e:
            logger.warning("Failed to inspect Wi-Fi networks via netsh: %s", e)

    top_wifi = wifi_networks[:5]
    if top_wifi:
        wifi_lines = [
            f"• *{w['ssid']}* (`{w['bssid']}`) — Signal: {w['signal']}"
            for w in top_wifi
        ]
        wifi_summary = "\n".join(wifi_lines)
    else:
        wifi_summary = "• _No nearby Wi-Fi networks detected or permission required._"

    formatted = (
        f"📍 *Location & Network Telemetry*\n\n"
        f"🌐 *Public IP:* `{public_ip}`\n"
        f"🏢 *ISP:* {isp}\n"
        f"🗺️ *Approx Location:* {loc_str}\n"
        f"📌 *Coordinates:* `{coords_str}`\n\n"
        f"📶 *Top Nearby Wi-Fi BSSIDs:*\n{wifi_summary}"
    )

    return AwaitableDict({
        "status": "success",
        "public_ip": public_ip,
        "isp": isp,
        "location": loc_str,
        "coordinates": coords_str,
        "wifi_networks": top_wifi,
        "formatted": formatted,
        "message": formatted,
    })


def lock_workstation() -> dict:
    """Immediately lock the Windows workstation and wipe clipboard content."""
    # Wipe clipboard
    try:
        if hasattr(ctypes, "windll") and hasattr(ctypes.windll, "user32"):
            if ctypes.windll.user32.OpenClipboard(0):
                ctypes.windll.user32.EmptyClipboard()
                ctypes.windll.user32.CloseClipboard()
    except Exception as ce:
        logger.debug("Could not clear clipboard: %s", ce)

    try:
        if sys.platform.startswith("win") and hasattr(ctypes, "windll") and hasattr(ctypes.windll, "user32"):
            ctypes.windll.user32.LockWorkStation()
            msg = "🔒 Windows workstation locked."
        else:
            msg = "🔒 Workstation locked (simulated on non-Windows platform)."
        return AwaitableDict({"status": "success", "message": msg})
    except Exception as e:
        logger.error("Failed to lock workstation: %s", e)
        return AwaitableDict({"status": "error", "message": f"Failed to lock workstation: {e}"})
