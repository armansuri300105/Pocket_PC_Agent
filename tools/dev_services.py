"""Developer Service Manager and Quick Tunnels.

Features:
1. list_running_services: Lists background dev processes (python, node, docker) with PID, port, CPU, and RAM.
2. start_named_service: Reads services.json and starts background project services asynchronously.
3. stop_named_service: Terminates tracked process trees cleanly using psutil.
4. get_service_logs: Retrieves rolling logs (last 30 lines) for a running service.
5. expose_port_tunnel: Spawns Cloudflare Quick Tunnels (cloudflared) and extracts temporary public URLs.
"""

from __future__ import annotations

import asyncio
import collections
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import shutil
from typing import Any, Deque, Dict, List, Optional, Union

import psutil

from core.config import get_settings
from core.sandbox import is_path_allowed
from core import project_inspector

logger = logging.getLogger(__name__)

DEFAULT_SERVICES_FILE = Path("./services.json")


@dataclass
class ManagedService:
    """Represents an active dev service managed by the agent."""
    name: str
    pid: int
    process: asyncio.subprocess.Process
    cmd: Union[List[str], str]
    cwd: str
    port: Optional[int] = None
    started_at: str = ""
    log_buffer: Deque[str] = field(default_factory=lambda: collections.deque(maxlen=30))
    reader_task: Optional[asyncio.Task] = None


# In-memory tracking registries
RUNNING_SERVICES: Dict[str, ManagedService] = {}
RUNNING_TUNNELS: Dict[int, Dict[str, Any]] = {}


def load_services_registry(services_file: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Load services definitions from services.json."""
    path = Path(services_file) if services_file else DEFAULT_SERVICES_FILE
    if not path.exists():
        # Provide default template
        sample = {
            "fastapi_demo": {
                "cwd": "./sandbox_files",
                "cmd": ["python", "-m", "http.server", "8000"],
                "port": 8000,
                "description": "Sample HTTP Server Demo",
            }
        }
        try:
            path.write_text(json.dumps(sample, indent=2), encoding="utf-8")
        except Exception:
            pass
        return sample

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error("Failed to parse services.json: %s", e)
        return {}


async def _capture_stream(stream: asyncio.StreamReader, buffer: Deque[str]) -> None:
    """Read lines from a process stream into a rolling deque buffer."""
    try:
        while True:
            line = await stream.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").rstrip()
            if text:
                buffer.append(text)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.debug("Stream reading terminated: %s", e)


async def list_running_services() -> Dict[str, Any]:
    """List running background dev processes (python, node, docker) with PID, port, CPU, and RAM."""
    def _scan() -> List[Dict[str, Any]]:
        target_names = {
            "python", "python.exe", "python3", "node", "node.exe",
            "docker", "dockerd", "dockerd.exe", "uvicorn", "uvicorn.exe",
            "npm", "yarn", "pnpm", "cargo", "go", "postgres", "redis-server",
        }

        results: List[Dict[str, Any]] = []

        for p in psutil.process_iter(["pid", "name", "cmdline", "cpu_percent", "memory_info"]):
            try:
                p_name = (p.info["name"] or "").lower()
                matched = any(t in p_name for t in target_names)

                if matched:
                    pid = p.info["pid"]
                    # Skip our own daemon process if needed, or include it labeled
                    mem_mb = (p.info["memory_info"].rss / (1024 * 1024)) if p.info["memory_info"] else 0.0

                    # Detect listening ports
                    ports = []
                    try:
                        for conn in p.net_connections():
                            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                                ports.append(conn.laddr.port)
                    except Exception:
                        pass

                    cmdline = p.info.get("cmdline") or []
                    cmd_str = " ".join(cmdline[:4]) if cmdline else p_name

                    results.append({
                        "pid": pid,
                        "name": p.info["name"],
                        "command": cmd_str,
                        "cpu_percent": p.info.get("cpu_percent", 0.0),
                        "memory_mb": round(mem_mb, 1),
                        "ports": sorted(list(set(ports))),
                        "managed": any(s.pid == pid for s in RUNNING_SERVICES.values()),
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return results

    procs = await asyncio.to_thread(_scan)

    # Format human-friendly summary
    if not procs:
        formatted = "ℹ️ No running developer services (Python, Node, Docker) detected."
    else:
        lines = [f"🛠️ *Running Developer Services ({len(procs)}):*"]
        for p in procs[:15]:
            port_str = f" | Ports: {', '.join(map(str, p['ports']))}" if p['ports'] else ""
            managed_str = " (Managed)" if p["managed"] else ""
            lines.append(
                f"• *{p['name']}* (PID: `{p['pid']}`){managed_str}\n"
                f"   RAM: {p['memory_mb']} MB | CPU: {p['cpu_percent']}%{port_str}\n"
                f"   Cmd: `{p['command']}`"
            )
        formatted = "\n".join(lines)

    return {
        "services": procs,
        "count": len(procs),
        "formatted": formatted,
    }


async def start_named_service(
    target: str,
    component: Optional[str] = None,
    services_file: Optional[Union[str, Path]] = None,
    allowed_dirs: Optional[List[Union[str, Path]]] = None,
) -> Dict[str, Any]:
    """Start a service defined in services.json or auto-detected by project_inspector."""
    raw_target = (target or "").strip()
    if not raw_target:
        raise ValueError("A valid 'target' (service name or project path) must be provided.")

    registry = load_services_registry(services_file)
    clean_name = raw_target
    lookup_key = f"{clean_name}_{component}" if component else clean_name

    cfg = None
    stack_name = "Custom Service"

    # 1. Exact match in services.json
    if lookup_key in registry:
        cfg = registry[lookup_key]
        clean_name = lookup_key
    elif clean_name in registry and not component:
        cfg = registry[clean_name]
    else:
        # 2. Path hint / project discovery via SmartFileResolver and project_inspector
        proj_dir = None
        try:
            from core.smart_resolver import SmartFileResolver
            candidate = SmartFileResolver.get_instance().resolve(clean_name, allowed_dirs=allowed_dirs)
            if candidate.is_file():
                candidate = candidate.parent
            if candidate.is_dir() and is_path_allowed(candidate, allowed_dirs=allowed_dirs):
                proj_dir = candidate
        except Exception as e:
            logger.debug("SmartFileResolver could not resolve '%s': %s", clean_name, e)

        if not proj_dir:
            proj_dir = project_inspector.find_project_dir(clean_name, allowed_dirs=allowed_dirs)

        if not proj_dir:
            available_str = ", ".join(f"`{k}`" for k in registry.keys()) or "None"
            raise KeyError(f"Could not find project directory matching '{clean_name}' in allowed paths. Available in services.json: {available_str}")

        if not is_path_allowed(proj_dir, allowed_dirs=allowed_dirs):
            raise PermissionError(f"Access denied: '{proj_dir}' is outside allowed directories.")

        components = project_inspector.inspect_project(proj_dir)
        if not components:
            raise KeyError(f"Project '{proj_dir.name}' found at `{proj_dir}`, but no runnable tech stack (FastAPI, Node, React, Docker) was detected.")

        spec = None
        if component:
            comp_clean = component.strip().lower()
            if comp_clean in components:
                spec = components[comp_clean]
            else:
                for k, s in components.items():
                    if comp_clean in k or comp_clean in s.stack.lower():
                        spec = s
                        break

        if not spec:
            if len(components) == 1:
                spec = list(components.values())[0]
            else:
                for priority in ("backend", "root", "docker", "frontend"):
                    if priority in components:
                        spec = components[priority]
                        break
                if not spec:
                    spec = list(components.values())[0]

        cfg = {
            "cwd": str(spec.cwd),
            "cmd": spec.cmd,
            "port": spec.port,
            "description": spec.description,
            "stack": spec.stack,
        }
        stack_name = spec.stack
        new_service_name = spec.project_name.lower()
        if spec.component and spec.component != "root" and len(components) > 1:
            new_service_name = f"{new_service_name}_{spec.component}"
        clean_name = new_service_name

        # Auto-save discovered service to services.json for instant reuse
        registry[clean_name] = cfg
        try:
            p = Path(services_file) if services_file else DEFAULT_SERVICES_FILE
            p.write_text(json.dumps(registry, indent=2), encoding="utf-8")
        except Exception as se:
            logger.warning("Could not auto-save discovered service to services.json: %s", se)

    raw_cmd = cfg.get("cmd")
    if not raw_cmd:
        raise ValueError(f"Service '{clean_name}' has no 'cmd' configured.")

    # Check if already running
    if clean_name in RUNNING_SERVICES:
        existing = RUNNING_SERVICES[clean_name]
        if psutil.pid_exists(existing.pid):
            return {
                "status": "already_running",
                "service_name": clean_name,
                "pid": existing.pid,
                "port": existing.port,
                "message": f"Service '{clean_name}' is already running with PID {existing.pid}.",
            }

    cwd_str = cfg.get("cwd", ".")
    cwd_path = Path(cwd_str).resolve()
    # Enforce directory jail on working directory
    if not is_path_allowed(cwd_path, allowed_dirs=allowed_dirs):
        raise PermissionError(f"Service working directory '{cwd_path}' is outside allowed directories.")
    cwd_path.mkdir(parents=True, exist_ok=True)

    log_buffer: Deque[str] = collections.deque(maxlen=30)

    # Spawn process
    try:
        if isinstance(raw_cmd, list):
            proc = await asyncio.create_subprocess_exec(
                *raw_cmd,
                cwd=str(cwd_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            proc = await asyncio.create_subprocess_shell(
                str(raw_cmd),
                cwd=str(cwd_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
    except (PermissionError, OSError) as e:
        logger.error("OS/AV blocked process for service '%s': %s", clean_name, e)
        return {
            "status": "error",
            "service_name": clean_name,
            "port": cfg.get("port"),
            "message": f"Failed to start service '{clean_name}'. Windows Defender or local Antivirus may have blocked execution: {e}",
        }

    # Start log capture
    async def _capture_all():
        if proc.stdout and proc.stderr:
            await asyncio.gather(
                _capture_stream(proc.stdout, log_buffer),
                _capture_stream(proc.stderr, log_buffer),
            )

    reader_task = asyncio.create_task(_capture_all())

    managed = ManagedService(
        name=clean_name,
        pid=proc.pid,
        process=proc,
        cmd=raw_cmd,
        cwd=str(cwd_path),
        port=cfg.get("port"),
        started_at=datetime.now(timezone.utc).isoformat(),
        log_buffer=log_buffer,
        reader_task=reader_task,
    )
    RUNNING_SERVICES[clean_name] = managed

    # Wait 0.5s to verify startup
    await asyncio.sleep(0.5)

    initial_logs = list(log_buffer)
    port_text = f" | Port: `{cfg.get('port')}`" if cfg.get('port') else ""
    return {
        "status": "started",
        "service_name": clean_name,
        "pid": proc.pid,
        "port": cfg.get("port"),
        "logs": initial_logs,
        "message": (
            f"🚀 *Started Service:* `{clean_name}`\n"
            f"• *Stack*: {stack_name}\n"
            f"• *PID*: `{proc.pid}`{port_text}\n"
            f"• *Directory*: `{cwd_path}`\n"
            f"• *Command*: `{' '.join(raw_cmd) if isinstance(raw_cmd, list) else raw_cmd}`"
        ),
    }


async def stop_named_service(target: str) -> Dict[str, Any]:
    """Gracefully terminate a tracked service or Cloudflare tunnel using psutil."""
    clean_target = (target or "").strip()
    if not clean_target:
        raise ValueError("A valid 'target' (service name or tunnel port) must be provided.")

    def _terminate_tree(pid: int) -> None:
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                child.terminate()
            parent.terminate()
            gone, alive = psutil.wait_procs(children + [parent], timeout=3.0)
            for p in alive:
                p.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # 1. Check if target is a Cloudflare tunnel (e.g. "tunnel 5173" or "5173")
    port: Optional[int] = None
    tunnel_match = re.match(r"^tunnel(?:\s+(?:on|port))?\s+(\d+)$", clean_target, re.IGNORECASE)
    if tunnel_match:
        port = int(tunnel_match.group(1))
    elif clean_target.isdigit():
        port = int(clean_target)
    elif clean_target.lower().startswith("tunnel "):
        digits = re.findall(r"\b\d+\b", clean_target)
        if digits:
            port = int(digits[0])

    if port is not None and port in RUNNING_TUNNELS:
        tunnel_info = RUNNING_TUNNELS.pop(port)
        pid = tunnel_info.get("pid")
        if pid:
            await asyncio.to_thread(_terminate_tree, pid)
        proc = tunnel_info.get("proc")
        if proc and getattr(proc, "returncode", None) is None:
            try:
                proc.kill()
            except Exception:
                pass
        return {
            "status": "success",
            "message": f"Successfully stopped Cloudflare tunnel on port {port}.",
        }

    if clean_target.lower().startswith("tunnel "):
        return {
            "status": "not_running",
            "service_name": clean_target,
            "message": f"Cloudflare tunnel on port {port} is not currently running." if port else f"Invalid tunnel target '{clean_target}'.",
        }

    # 2. Standard service lookup
    clean_name = clean_target
    if clean_name not in RUNNING_SERVICES:
        return {
            "status": "not_running",
            "service_name": clean_name,
            "message": f"Service '{clean_name}' is not currently running.",
        }

    managed = RUNNING_SERVICES.pop(clean_name)
    await asyncio.to_thread(_terminate_tree, managed.pid)

    if managed.reader_task and not managed.reader_task.done():
        managed.reader_task.cancel()

    return {
        "status": "stopped",
        "service_name": clean_name,
        "pid": managed.pid,
        "message": f"🛑 Stopped service '{clean_name}' (PID: {managed.pid}).",
    }


def get_service_logs(service_name: str, lines: int = 30) -> str:
    """Retrieve the last N lines of stdout/stderr logs from a managed service."""
    clean_name = service_name.strip()
    if clean_name not in RUNNING_SERVICES:
        return f"Service '{clean_name}' is not currently running."

    buffer = RUNNING_SERVICES[clean_name].log_buffer
    recent = list(buffer)[-lines:]
    if not recent:
        return f"No logs available yet for '{clean_name}'."
    return "\n".join(recent)


async def expose_port_tunnel(port: int, timeout: float = 15.0) -> Dict[str, Any]:
    """Spawn Cloudflare Quick Tunnel (cloudflared) and extract public URL."""
    if port in RUNNING_TUNNELS:
        active = RUNNING_TUNNELS[port]
        return {
            "status": "already_active",
            "port": port,
            "url": active["url"],
            "pid": active["pid"],
            "message": f"🔗 Cloudflare tunnel already active: {active['url']}",
        }

    # Verify cloudflared executable is available
    cloudflared_bin = shutil.which("cloudflared")
    if not cloudflared_bin:
        raise FileNotFoundError(
            "The 'cloudflared' binary was not found in PATH. "
            "Please install Cloudflared from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/ "
            "to enable Quick Tunnels."
        )

    cmd = [cloudflared_bin, "tunnel", "--url", f"http://localhost:{port}"]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (PermissionError, OSError) as e:
        logger.error("OS/AV blocked cloudflared tunnel on port %s: %s", port, e)
        return {
            "status": "error",
            "message": "Failed to launch tunnel. Windows Defender or local Antivirus may have blocked or quarantined the cloudflared executable.",
        }

    re_url = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")
    extracted_url: Optional[str] = None

    async def _read_stderr() -> Optional[str]:
        if not proc.stderr:
            return None
        try:
            while True:
                if isinstance(proc.returncode, int) and proc.returncode != 0:
                    break
                line = await proc.stderr.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace")
                match = re_url.search(text)
                if match:
                    return match.group(0)
        except (PermissionError, OSError) as e:
            logger.warning("Error reading stderr for cloudflared: %s", e)
            return None
        return None

    try:
        extracted_url = await asyncio.wait_for(_read_stderr(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return {
            "status": "error",
            "message": f"Timed out waiting for Cloudflare Tunnel URL on port {port}.",
        }
    except (PermissionError, OSError) as e:
        logger.error("OS/AV error during cloudflared execution: %s", e)
        try:
            proc.kill()
        except Exception:
            pass
        return {
            "status": "error",
            "message": "Failed to launch tunnel. Windows Defender or local Antivirus may have blocked or quarantined the cloudflared executable.",
        }

    if not extracted_url:
        try:
            proc.kill()
        except Exception:
            pass
        return {
            "status": "error",
            "message": "Failed to launch tunnel. Windows Defender or local Antivirus may have blocked or quarantined the cloudflared executable.",
        }

    RUNNING_TUNNELS[port] = {
        "port": port,
        "url": extracted_url,
        "pid": proc.pid,
        "proc": proc,
    }

    return {
        "status": "active",
        "port": port,
        "url": extracted_url,
        "pid": proc.pid,
        "message": f"🔗 *Live Cloudflare Tunnel:*\n{extracted_url}",
    }
