"""Bounded AI Planner with Pre-Flight Secret Scrubbing, Strict Tier Gating, and Token Optimization.

Connects to Ollama (http://localhost:11434/v1) or any OpenAI-compatible API.
Enforces:
1. Pre-flight secret scrubbing via core.scrubber.
2. Max 6 steps cap to prevent infinite loops.
3. Every tool call deterministically evaluated via core.permissions.
   Tier 2 and Tier 3 pause execution for user confirmation/PIN.
   Tier 4 is strictly blocked.
4. Token Optimization & Tool-Call Resilience:
   - Minified schemas grouped into domain buckets.
   - select_relevant_tools() filters tool definitions per user intent.
   - parse_inline_tool_call() intercepts Qwen XML & inline tool calls in message.content.
   - Zero-token 400 tool_use_failed recovery.
   - Terminal tool short-circuit (skips redundant second LLM call).
   - Relative path compression and 600-char truncation in session_messages.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import uuid

import httpx

from core.config import get_settings
from core import db
from core.fast_router import ToolCall
from core.permissions import SecurityTier, get_tool_tier
from core import sandbox
from core.scrubber import scrub_secrets
from core import project_inspector
from tools import system_tools, dev_services

logger = logging.getLogger(__name__)

# Maximum allowable steps per plan execution
MAX_PLANNER_STEPS = 6

# Terminal tools that complete an action with self-descriptive output
TERMINAL_TOOLS: Set[str] = {
    "capture_screenshot",
    "explore_path",
    "deliver_path",
    "zip_and_prepare",
    "expose_port_tunnel",
    "start_named_service",
    "stop_named_service",
    "safe_delete",
    "safe_move",
    "undo_last_action",
    "kill_process",
}

# Verbs/phrases indicating user requested subsequent analytical synthesis
ANALYTICAL_KEYWORDS: Set[str] = {
    "tell me",
    "compare",
    "analyze",
    "how much",
    "size",
    "explain",
    "check and",
    "verify",
}

# Common model tool aliases mapped to standard tool names
ALIAS_TOOL_MAP: Dict[str, str] = {
    "explore_path": "explore_path",
    "explore": "explore_path",
    "list_directory": "explore_path",
    "list_dir": "explore_path",
    "list_dirs": "explore_path",
    "list_folders": "explore_path",
    "get_folders": "explore_path",
    "ls": "explore_path",
    "dir": "explore_path",
    "find_file": "explore_path",
    "find_files": "explore_path",
    "search_files": "explore_path",
    "deliver_path": "deliver_path",
    "deliver": "deliver_path",
    "send_file": "deliver_path",
    "send_folder_files": "deliver_path",
    "send": "deliver_path",
    "download": "deliver_path",
    "screenshot": "capture_screenshot",
    "vitals": "get_system_vitals",
    "run_project": "start_named_service",
    "start_project": "start_named_service",
    "run_service": "start_named_service",
    "start_service": "start_named_service",
    "kill_process": "kill_process",
    "kill": "kill_process",
    "kill_pid": "kill_process",
    "terminate_process": "kill_process",
}

# ---------------------------------------------------------------------
# Task 3.1 & 3.2: Minified & Partitioned Tool Schemas (descriptions <= 12 words)
# ---------------------------------------------------------------------

FILE_TOOL_SCHEMAS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "explore_path",
            "description": "Explore files and folders in directory or inspect a file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Path or folder name to explore.",
                    },
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "deliver_path",
            "description": "Send file or zip folder and deliver to user.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Path or name of file or folder to deliver.",
                    },
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "safe_delete",
            "description": "Safely delete a file or directory by moving it to undo storage.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_path": {
                        "type": "string",
                        "description": "The file or folder path. You MUST provide ONLY the exact path or filename. Strip all conversational text like 'the file named' or 'present in'.",
                    },
                    "path": {
                        "type": "string",
                        "description": "The file or folder path. Provide ONLY the exact path or filename.",
                    },
                },
                "required": ["target_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "safe_move",
            "description": "Safely move or rename a file or directory within allowed folders.",
            "parameters": {
                "type": "object",
                "properties": {
                    "src": {
                        "type": "string",
                        "description": "The file or folder path. You MUST provide ONLY the exact path or filename. Strip all conversational text like 'the file named' or 'present in'.",
                    },
                    "dst": {
                        "type": "string",
                        "description": "The destination file or folder path. You MUST provide ONLY the exact path or filename. Strip all conversational text like 'the file named' or 'present in'.",
                    },
                    "source_path": {
                        "type": "string",
                        "description": "The source file or folder path. Provide ONLY the exact path or filename.",
                    },
                    "destination_path": {
                        "type": "string",
                        "description": "The destination file or folder path. You MUST provide ONLY the exact path or filename. Strip all conversational text like 'the file named' or 'present in'.",
                    },
                },
                "required": ["src", "dst"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "undo_last_action",
            "description": "Restore last deleted or modified file.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]

DEV_TOOL_SCHEMAS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_running_services",
            "description": "List running dev services with ports and usage.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_named_service",
            "description": "Start, run, or launch a developer project, web server, or application. Accepts a registered service name OR a directory path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Registered service name or directory path to project.",
                    },
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "stop_named_service",
            "description": "Stop a managed background developer service or Cloudflare tunnel by registered name or port.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Registered service name, tunnel name, or tunnel port (e.g. 'tunnel 5173' or '5173').",
                    },
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_project",
            "description": "Detect project tech stack, components, and startup command.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_name": {"type": "string"},
                    "component": {"type": "string"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "expose_port_tunnel",
            "description": "Create public Cloudflare tunnel for local port.",
            "parameters": {
                "type": "object",
                "properties": {
                    "port": {"type": "integer"},
                },
                "required": ["port"],
            },
        },
    },
]

SYS_TOOL_SCHEMAS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "get_system_vitals",
            "description": "Get CPU, RAM, disk, and battery vitals.",
            "parameters": {
                "type": "object",
                "properties": {
                    "component": {"type": "string"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "capture_screenshot",
            "description": "Capture screenshot of current desktop screen.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "Execute specific explicit CLI commands (e.g., git status, pip install). DO NOT use this tool to 'run' or 'start' projects, apps, or servers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "cmd": {"type": "string"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "kill_process",
            "description": "Terminate or kill an arbitrary OS process using its numeric PID (Process ID). Use this ONLY when the user explicitly provides a PID number.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Numeric process ID (PID) to terminate.",
                    },
                },
                "required": ["pid"],
            },
        },
    },
]

TOOL_SCHEMAS: List[Dict[str, Any]] = FILE_TOOL_SCHEMAS + DEV_TOOL_SCHEMAS + SYS_TOOL_SCHEMAS
ALL_COMPACT_SCHEMAS: List[Dict[str, Any]] = TOOL_SCHEMAS
AVAILABLE_TOOL_NAMES: List[str] = [t["function"]["name"] for t in ALL_COMPACT_SCHEMAS]
TOOL_SCHEMA_MAP: Dict[str, Dict[str, Any]] = {
    t["function"]["name"]: t["function"] for t in ALL_COMPACT_SCHEMAS
}

# Domain keywords for bucket routing
FILE_KEYWORDS: Set[str] = {
    "file", "files", "folder", "folders", "directory", "dir", "dirs",
    "find", "search", "locate", "send", "deliver", "download", "zip",
    "archive", "compress", "delete", "remove", "move", "mv", "undo",
    "restore", "pdf", "image", "images", "photo", "photos", "pic", "pics",
    "doc", "docs", "document", "documents", "video", "videos", "resume",
    "list", "ls", "contents", "present", "explore",
}

DEV_KEYWORDS: Set[str] = {
    "service", "services", "server", "backend", "frontend", "api", "app",
    "docker", "port", "tunnel", "cloudflare", "inspect", "stack", "start",
    "launch", "stop", "node", "fastapi", "react", "nextjs", "python", "dev",
    "project", "projects", "run",
}

SYS_KEYWORDS: Set[str] = {
    "vitals", "system", "cpu", "ram", "memory", "disk", "battery", "power",
    "screen", "screenshot", "shot", "shell", "cmd", "bash", "terminal",
    "exec", "specs", "pc", "laptop",
}


def select_relevant_tools(prompt: str) -> List[Dict[str, Any]]:
    """Select minified tool schema buckets based on keywords in prompt.

    Returns union of matched domain buckets, or all schemas if no domain keywords match.
    """
    if not prompt:
        return list(TOOL_SCHEMAS)

    words = set(re.findall(r"\b\w+\b", prompt.lower()))

    selected: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def _add_bucket(bucket: List[Dict[str, Any]]) -> None:
        for tool in bucket:
            name = tool["function"]["name"]
            if name not in seen:
                seen.add(name)
                selected.append(tool)

    matched = False
    if words & FILE_KEYWORDS:
        _add_bucket(FILE_TOOL_SCHEMAS)
        matched = True
    if words & DEV_KEYWORDS:
        _add_bucket(DEV_TOOL_SCHEMAS)
        matched = True
    if words & SYS_KEYWORDS:
        _add_bucket(SYS_TOOL_SCHEMAS)
        matched = True

    if not matched:
        return list(TOOL_SCHEMAS)

    return selected


# ---------------------------------------------------------------------
# Compression Helpers
# ---------------------------------------------------------------------


def compress_tool_output(
    output: str,
    allowed_dirs: Optional[List[Path]] = None,
    max_len: int = 600,
) -> str:
    """Compress tool output for LLM message history:
    1. Strip absolute ALLOWED_DIRS prefixes so only relative paths remain.
    2. Redact sensitive credentials via scrub_secrets.
    3. Truncate to max_len (600) characters.
    """
    if not output:
        return output

    try:
        dirs = allowed_dirs or get_settings().ALLOWED_DIRS
    except Exception:
        dirs = []

    compressed = output
    for d in dirs:
        d_path = Path(d).resolve()
        resolved_str = str(d_path)
        compressed = compressed.replace(resolved_str + "\\", "")
        compressed = compressed.replace(resolved_str + "/", "")
        compressed = compressed.replace(resolved_str, "")
        fwd_str = resolved_str.replace("\\", "/")
        compressed = compressed.replace(fwd_str + "/", "")
        compressed = compressed.replace(fwd_str, "")

    compressed = scrub_secrets(compressed)

    if len(compressed) > max_len:
        compressed = compressed[:max_len]

    return compressed


# ---------------------------------------------------------------------
# Inline XML / JSON Tool Call Parser & 400 Recovery
# ---------------------------------------------------------------------


def _clean_and_coerce_args(raw_args: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Coerce stringified booleans ('true'/'false') and integers ('8000') in tool arguments."""
    cleaned: Dict[str, Any] = {}
    if not raw_args or not isinstance(raw_args, dict):
        return cleaned

    INT_ARG_KEYS = {"port", "pid", "step", "count", "interval", "timeout"}

    for k, v in raw_args.items():
        if isinstance(v, str):
            v_str = v.strip()
            # Boolean coercion
            if v_str.lower() in ("true", "yes", "1") and k.lower() in ("folders_only", "files_only", "verbose"):
                cleaned[k] = True
            elif v_str.lower() in ("false", "no", "0") and k.lower() in ("folders_only", "files_only", "verbose"):
                cleaned[k] = False
            elif v_str.lower() == "true":
                cleaned[k] = True
            elif v_str.lower() == "false":
                cleaned[k] = False
            # Integer coercion
            elif (k.lower() in INT_ARG_KEYS or k.lower().endswith("_port")) and v_str.isdigit():
                cleaned[k] = int(v_str)
            else:
                cleaned[k] = v_str
        else:
            cleaned[k] = v

    if "target" not in cleaned:
        for alias_k in ("name", "service_name", "service", "project_name", "project"):
            if alias_k in cleaned:
                cleaned["target"] = cleaned[alias_k]
                break

    return cleaned


def parse_inline_tool_call(content: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Detect and parse XML or JSON tool calls inside raw LLM text/content.

    Handles:
    1. Qwen XML syntax:
       <tool_call>
       <function=list_directory>
       <parameter=path>
       D_drive/projects
       </parameter>
       </function>
       </tool_call>
    2. Tag with attributes:
       <function name="list_directory">
       <parameter name="path">D_drive/projects</parameter>
       </function>
    3. JSON inside <tool_call>:
       <tool_call>
       {"name": "list_directory", "arguments": {"path": "D_drive/projects"}}
       </tool_call>
    """
    if not content:
        return None

    # Strip <think>...</think> blocks first
    text = re.sub(r"<think>[\s\S]*?</think>", "", content, flags=re.IGNORECASE).strip()

    # 1. Check for Qwen/Hermes XML syntax: <function=name> or <function name="name">
    fn_match = re.search(
        r"<function(?:=\s*|\s+name=[\"']?\s*)([a-zA-Z0-9_]+)\s*[\"']?[^>]*>([\s\S]*?)(?:</function>|$)",
        text,
        re.IGNORECASE,
    )
    if fn_match:
        raw_name = fn_match.group(1).strip()
        inner_params = fn_match.group(2)

        raw_args: Dict[str, Any] = {}
        param_matches = re.finditer(
            r"<parameter(?:=\s*|\s+name=[\"']?\s*)([a-zA-Z0-9_]+)\s*[\"']?[^>]*>([\s\S]*?)(?:</parameter>|(?=<parameter|</function|$))",
            inner_params,
            re.IGNORECASE,
        )
        for p in param_matches:
            p_name = p.group(1).strip()
            p_val = p.group(2).strip()
            raw_args[p_name] = p_val

        tool_name = ALIAS_TOOL_MAP.get(raw_name.lower(), raw_name)
        args = _clean_and_coerce_args(raw_args)
        return tool_name, args

    # 2. Check for JSON inside <tool_call>...</tool_call>
    tc_block_match = re.search(r"<tool_call>([\s\S]*?)(?:</tool_call>|$)", text, re.IGNORECASE)
    if tc_block_match:
        tc_text = tc_block_match.group(1).strip()
    else:
        tc_text = text

    # Strip markdown fences
    tc_clean = re.sub(r"^```(?:json|xml)?", "", tc_text.strip(), flags=re.MULTILINE)
    tc_clean = re.sub(r"```$", "", tc_clean.strip(), flags=re.MULTILINE).strip()

    # Try JSON parse
    parsed = None
    try:
        parsed = json.loads(tc_clean)
    except Exception:
        json_match = re.search(r"\{[\s\S]*\}", tc_clean)
        if json_match:
            try:
                parsed = json.loads(json_match.group(0))
            except Exception:
                pass

    if isinstance(parsed, dict):
        if "function" in parsed and isinstance(parsed["function"], dict):
            parsed = parsed["function"]

        name = parsed.get("name") or parsed.get("tool") or parsed.get("tool_name")
        if name and isinstance(name, str):
            raw_args = parsed.get("arguments") or parsed.get("parameters") or parsed.get("args") or {}
            if isinstance(raw_args, str):
                try:
                    raw_args = json.loads(raw_args)
                except Exception:
                    raw_args = {}
            if not isinstance(raw_args, dict):
                raw_args = {}

            tool_name = ALIAS_TOOL_MAP.get(name.lower(), name)
            args = _clean_and_coerce_args(raw_args)
            return tool_name, args

    return None


def recover_failed_tool_call(error_payload: Union[Dict[str, Any], str]) -> Optional[ToolCall]:
    """Recover tool call from 400 tool_use_failed / failed_generation payload without re-calling LLM."""
    if not error_payload:
        return None

    if isinstance(error_payload, str):
        try:
            error_payload = json.loads(error_payload)
        except Exception:
            pass

    raw_text = ""
    if isinstance(error_payload, dict):
        raw_text = (
            error_payload.get("failed_generation")
            or (
                error_payload.get("error", {}).get("failed_generation")
                if isinstance(error_payload.get("error"), dict)
                else None
            )
        ) or ""
        if not raw_text:
            err = error_payload.get("error")
            if isinstance(err, dict):
                raw_text = err.get("message") or str(err)
            elif isinstance(err, str):
                raw_text = err
            else:
                raw_text = json.dumps(error_payload)
    else:
        raw_text = str(error_payload)

    if not raw_text:
        return None

    parsed = parse_inline_tool_call(raw_text)
    if not parsed:
        return None

    name, args = parsed
    tier = get_tool_tier(name, args)

    return ToolCall(
        tool_name=name,
        args=args,
        tier=tier,
        raw_command=f"{name} {args}",
    )


# ---------------------------------------------------------------------
# Planner Result Dataclass
# ---------------------------------------------------------------------


@dataclass
class PlannerResult:
    """Outcome of an AI Planner execution session."""
    completed: bool
    final_message: str = ""
    intermediate_message: Optional[str] = None
    executed_steps: List[ToolCall] = field(default_factory=list)
    paused_for_approval: bool = False
    paused_tool_call: Optional[ToolCall] = None
    pending_tool_call: Optional[ToolCall] = None
    paused_call_id: Optional[str] = None
    tier: Optional[Union[SecurityTier, int]] = None
    session_messages: List[Dict[str, Any]] = field(default_factory=list)
    step_count: int = 0
    error: Optional[str] = None

    def __post_init__(self):
        if self.paused_tool_call is None and self.pending_tool_call is not None:
            self.paused_tool_call = self.pending_tool_call
        elif self.pending_tool_call is None and self.paused_tool_call is not None:
            self.pending_tool_call = self.paused_tool_call
        if self.tier is None and self.paused_tool_call is not None:
            self.tier = getattr(self.paused_tool_call, "tier", None)


# ---------------------------------------------------------------------
# Local Tool Dispatcher
# ---------------------------------------------------------------------


async def execute_tool_locally(tool_name: str, args: Dict[str, Any]) -> str:
    """Execute a tool locally and format output as a string for LLM feedback."""
    try:
        if tool_name == "explore_path":
            target = args.get("target") or args.get("path") or args.get("folder") or args.get("query") or "."
            res = await system_tools.explore_path(target)
            return res.get("formatted", str(res))

        elif tool_name == "deliver_path":
            target = args.get("target") or args.get("path") or args.get("file") or args.get("folder") or ""
            res = await system_tools.deliver_path(target)
            return str(res)

        elif tool_name == "list_directory":
            path = args.get("path") or args.get("folder") or args.get("directory") or "."
            folders_only = bool(args.get("folders_only", False))
            files_only = bool(args.get("files_only", False))
            res = await system_tools.list_directory(path, folders_only=folders_only, files_only=files_only)
            return res["formatted"]

        elif tool_name == "get_system_vitals":
            vitals = await system_tools.get_system_vitals()
            return vitals["formatted"]

        elif tool_name == "capture_screenshot":
            path = await system_tools.capture_screenshot()
            return f"Screenshot saved successfully at: {path}"

        elif tool_name == "find_files":
            query = args.get("query") or args.get("path") or args.get("name") or args.get("directory") or args.get("folder") or ""
            matches = await system_tools.find_files(query)
            return json.dumps(matches)

        elif tool_name == "send_file":
            target = args.get("target") or args.get("path") or args.get("name") or args.get("file") or ""
            resolved = await system_tools.resolve_file_for_sending(target)
            return f"FILE_SENT_SUCCESS:{resolved}"

        elif tool_name == "send_folder_files":
            folder = args.get("folder") or args.get("path") or args.get("dir") or args.get("target") or ""
            cat = args.get("category") or "all"
            pkg = await system_tools.package_folder_files(folder, category=cat)
            return json.dumps({
                "status": "success",
                "zip_path": str(pkg["zip_path"]) if pkg["zip_path"] else "",
                "file_count": pkg["file_count"],
                "category": pkg["category"],
                "folder_name": pkg["folder_name"],
                "total_bytes": pkg["total_bytes"],
            })

        elif tool_name == "safe_delete":
            target_path = args.get("target_path") or args.get("path") or args.get("target") or ""
            res = await sandbox.safe_delete(target_path)
            if res.get("status") == "error":
                return f"Error: {res.get('message')}"
            return f"File moved to undo storage: {res['original_path']} (undo_id={res['undo_id']})"

        elif tool_name == "safe_move":
            src = args.get("src") or args.get("source") or args.get("source_path") or args.get("target_path") or ""
            dst = args.get("dst") or args.get("destination") or args.get("dest") or args.get("destination_path") or ""
            res = await sandbox.safe_move(src, dst)
            if res.get("status") == "error":
                return f"Error: {res.get('message')}"
            return f"Moved file to: {res['destination_path']}"

        elif tool_name == "zip_and_prepare":
            path = args.get("path") or args.get("folder") or args.get("target") or ""
            zip_path = await system_tools.zip_and_prepare(path)
            return f"Created zip archive: {zip_path}"

        elif tool_name == "undo_last_action":
            res = await sandbox.undo_last_action()
            if res:
                return f"Restored {res['action_type']} for {res['original_path']}"
            return "No previous actions to undo."

        elif tool_name == "run_shell":
            cmd = args.get("command") or args.get("cmd") or args.get("shell") or ""
            res = await system_tools.run_shell(cmd)
            if res.get("status") == "error":
                return f"Error: {res.get('message')}"
            return res.get("output", res.get("message", "(Command succeeded with no output)"))

        elif tool_name == "list_running_services":
            res = await dev_services.list_running_services()
            return res["formatted"]

        elif tool_name == "start_named_service":
            svc = args.get("target") or args.get("service_name") or args.get("name") or args.get("service") or ""
            comp = args.get("component")
            res = await dev_services.start_named_service(target=svc, component=comp)
            return res["message"]

        elif tool_name == "stop_named_service":
            svc = args.get("target") or args.get("service_name") or args.get("name") or args.get("service") or ""
            res = await dev_services.stop_named_service(target=svc)
            return res["message"]

        elif tool_name == "inspect_project":
            proj = args.get("project_name") or args.get("name") or args.get("query") or ""
            comp = args.get("component")
            spec, avail, msg = project_inspector.resolve_service_to_start(proj, component=comp)
            if spec:
                return json.dumps(spec.to_dict())
            return json.dumps({"error": msg, "available": [s.to_dict() for s in avail]})

        elif tool_name == "expose_port_tunnel":
            port = int(args.get("port", 8000))
            res = await dev_services.expose_port_tunnel(port)
            if res.get("status") == "error":
                return f"Error: {res.get('message')}"
            return res.get("message", str(res))

        elif tool_name == "kill_process":
            raw_pid = args.get("pid") or args.get("target") or args.get("id") or 0
            res = await system_tools.kill_process(pid=raw_pid)
            return res.get("message", str(res))

        else:
            return f"Unknown tool: {tool_name}"

    except Exception as e:
        logger.error("Error executing tool %s locally: %s", tool_name, e)
        return f"Error executing {tool_name}: {str(e)}"


# ---------------------------------------------------------------------
# AI Planner Core Class
# ---------------------------------------------------------------------


class AIPlanner:
    """Bounded AI Planner coordinating LLM tool calls within safety boundaries."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_steps: int = MAX_PLANNER_STEPS,
    ):
        settings = get_settings()
        self.base_url = (base_url or settings.LLM_BASE_URL).rstrip("/")
        self.api_key = api_key or settings.LLM_API_KEY
        self.model = model or settings.LLM_MODEL
        self.max_steps = max_steps
        self.pending_tool_queue: List[ToolCall] = []
        self.is_compound_request: bool = False
        self.completed_steps_in_turn: int = 0
        self.current_intermediate_message: Optional[str] = None
        self.active_schemas: Optional[List[Dict[str, Any]]] = None

    def _should_short_circuit(self, tool_name: str, is_analytical: bool) -> bool:
        if is_analytical:
            return False
        return (
            tool_name in TERMINAL_TOOLS
            and not self.pending_tool_queue
            and not (self.is_compound_request and self.completed_steps_in_turn < 2)
        )

    async def _call_llm(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Send chat completion request to Ollama / OpenAI-compatible endpoint.

        Sets temperature=0.0 and omits tool parameters when tools=None to save input tokens.
        """
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.0,
        }
        if tools is not None and len(tools) > 0:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            return resp.json()

    async def plan_and_execute(
        self,
        user_prompt: str,
        session_messages: Optional[List[Dict[str, Any]]] = None,
        executed_steps: Optional[List[ToolCall]] = None,
        step_count: int = 0,
        intermediate_message: Optional[str] = None,
    ) -> PlannerResult:
        """Execute or resume an AI planning session.

        Pre-flight secret scrubbing is applied before sending prompt to the LLM.
        """
        steps_history: List[ToolCall] = list(executed_steps or [])
        self.current_intermediate_message = intermediate_message

        if session_messages is None:
            self.pending_tool_queue = []
            self.completed_steps_in_turn = 0
            self.is_compound_request = bool(re.search(r'\b(and|then|afterwards|also)\b', user_prompt, re.IGNORECASE))
            self.active_schemas = select_relevant_tools(user_prompt)
            # 1. Pre-flight secret scrubbing
            scrubbed_input = scrub_secrets(user_prompt)
            # Concise system prompt under 65 tokens with /no_think
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are PocketPC Agent. Use tools when needed. "
                        "Return concise answers. Start services via start_named_service. "
                        "If the user requests multiple actions (e.g., 'start X and expose port Y'), "
                        "emit all required tool calls in order, or emit the next required tool call "
                        "immediately after receiving the first tool's result. /no_think"
                    ),
                },
                {"role": "user", "content": scrubbed_input},
            ]
            effective_prompt = user_prompt
        else:
            messages = list(session_messages)
            effective_prompt = user_prompt
            if not effective_prompt:
                for m in session_messages:
                    if m.get("role") == "user":
                        effective_prompt = m.get("content", "")
                        break
            if not self.is_compound_request and effective_prompt:
                self.is_compound_request = bool(re.search(r'\b(and|then|afterwards|also)\b', effective_prompt, re.IGNORECASE))
            if not self.active_schemas:
                self.active_schemas = select_relevant_tools(effective_prompt)

        is_analytical = any(keyword in effective_prompt.lower() for keyword in ANALYTICAL_KEYWORDS)
        if not self.active_schemas:
            self.active_schemas = select_relevant_tools(effective_prompt)
        current_step = step_count

        while current_step < self.max_steps:
            current_step += 1

            # Keep active_schemas attached during active steps so the model uses native tool calling.
            # Only omit tools (tools=None) if all tools have executed and an analytical summary is requested.
            if len(steps_history) > 0 and is_analytical:
                tools_to_pass: Optional[List[Dict[str, Any]]] = None
            else:
                tools_to_pass = self.active_schemas

            try:
                data = await self._call_llm(messages, tools=tools_to_pass)
            except (httpx.ConnectError, httpx.TimeoutException) as conn_err:
                logger.error("LLM connection failed: %s", conn_err)
                return PlannerResult(
                    completed=False,
                    final_message=(
                        f"⚠️ AI Planner unreachable at `{self.base_url}`. "
                        f"Ensure local Ollama (`ollama serve`) or the configured LLM endpoint is online."
                    ),
                    executed_steps=steps_history,
                    session_messages=messages,
                    step_count=current_step,
                    error=str(conn_err),
                )
            except httpx.HTTPStatusError as http_err:
                # Task 3.2: 400 tool_use_failed recovery
                if http_err.response.status_code == 400:
                    try:
                        err_json = http_err.response.json()
                    except Exception:
                        err_json = {}
                    err_text = http_err.response.text
                    if "tool_use_failed" in err_text.lower() or "failed_generation" in err_text.lower():
                        recovered_tc = recover_failed_tool_call(err_json or err_text)
                        if recovered_tc:
                            logger.info("Recovered failed tool call from 400: %s", recovered_tc.tool_name)
                            tool_name = recovered_tc.tool_name
                            args = recovered_tc.args
                            tier = recovered_tc.tier
                            call_id = "recovered_call"

                            # Task 3.1: Intercept unknown tool before permission gate
                            if tool_name not in AVAILABLE_TOOL_NAMES:
                                logger.warning("Recovered tool call is unknown: %s", tool_name)
                                messages.append({
                                    "role": "tool",
                                    "tool_call_id": call_id,
                                    "name": tool_name,
                                    "content": (
                                        f"Error: Tool '{tool_name}' does not exist. "
                                        f"Please use one of the provided tools (e.g., explore_path, deliver_path)."
                                    ),
                                })
                                continue

                            # Task 3.2: Intercept Malformed Arguments
                            schema = TOOL_SCHEMA_MAP.get(tool_name, {})
                            required_params = (
                                schema.get("parameters", {}).get("required", [])
                                or schema.get("required", [])
                            )
                            if required_params and (
                                not args
                                or not isinstance(args, dict)
                                or any(req not in args or args.get(req) is None or args.get(req) == "" for req in required_params)
                            ):
                                logger.warning("Recovered tool call '%s' missing required arguments: %s", tool_name, args)
                                messages.append({
                                    "role": "tool",
                                    "tool_call_id": call_id,
                                    "name": tool_name,
                                    "content": f"Error: You called '{tool_name}' but failed to provide the required arguments. Please emit the tool call again with valid JSON parameters.",
                                })
                                continue

                            # Tier 4: Blocked
                            if tier == SecurityTier.TIER_4_BLOCKED:
                                await db.log_audit(
                                    command=recovered_tc.raw_command,
                                    tier=4,
                                    status="BLOCKED",
                                    details="Recovered tool call blocked by Tier 4 security policy",
                                )
                                messages.append({
                                    "role": "tool",
                                    "tool_call_id": call_id,
                                    "content": "ERROR: Tool execution blocked by Tier 4 security policy.",
                                })
                                continue

                            # Tier 2 or Tier 3: Pause execution for user confirmation/PIN
                            if tier in (SecurityTier.TIER_2_CONFIRM, SecurityTier.TIER_3_PIN):
                                return PlannerResult(
                                    completed=False,
                                    paused_for_approval=True,
                                    paused_tool_call=recovered_tc,
                                    paused_call_id=call_id,
                                    session_messages=messages,
                                    step_count=current_step,
                                    executed_steps=steps_history,
                                )

                            # Tier 1: Auto-Execute
                            result_str = await execute_tool_locally(tool_name, args)
                            steps_history.append(recovered_tc)
                            compressed_out = compress_tool_output(result_str)
                            messages.append({
                                "role": "tool",
                                "tool_call_id": call_id,
                                "content": compressed_out,
                            })

                            # Task 3.3: Terminal tool short circuit
                            self.completed_steps_in_turn += 1
                            if self._should_short_circuit(tool_name, is_analytical):
                                return PlannerResult(
                                    completed=True,
                                    final_message=result_str,
                                    intermediate_message=self.current_intermediate_message,
                                    executed_steps=steps_history,
                                    session_messages=messages,
                                    step_count=current_step,
                                )
                            continue

                try:
                    err_json = http_err.response.json()
                    err_msg = err_json.get("error", {}).get("message", str(http_err))
                except Exception:
                    err_msg = str(http_err)
                logger.error("LLM HTTP error %s: %s", http_err.response.status_code, err_msg)
                return PlannerResult(
                    completed=False,
                    final_message=f"❌ AI Planner API error ({http_err.response.status_code}): `{err_msg}`",
                    executed_steps=steps_history,
                    session_messages=messages,
                    step_count=current_step,
                    error=err_msg,
                )
            except Exception as e:
                logger.error("LLM API error: %s", e)
                return PlannerResult(
                    completed=False,
                    final_message=f"❌ AI Planner API error: `{str(e)}`",
                    executed_steps=steps_history,
                    session_messages=messages,
                    step_count=current_step,
                    error=str(e),
                )

            choices = data.get("choices", [])
            if not choices:
                return PlannerResult(
                    completed=True,
                    final_message="No response received from model.",
                    executed_steps=steps_history,
                    session_messages=messages,
                    step_count=current_step,
                )

            msg = choices[0].get("message", {})
            tool_calls = msg.get("tool_calls", [])
            content = msg.get("content", "").strip()

            # Task 3.3: Intercept inline XML or JSON tool calls inside message.content
            if not tool_calls and content:
                inline_match = parse_inline_tool_call(content)
                if inline_match:
                    inline_name, inline_args = inline_match

                    # Task 3.1: Intercept unknown tools before permission gate
                    if inline_name not in AVAILABLE_TOOL_NAMES:
                        logger.warning("AI Planner intercepted unknown inline tool: %s", inline_name)
                        messages.append(msg)
                        messages.append({
                            "role": "tool",
                            "tool_call_id": "inline_call_0",
                            "name": inline_name,
                            "content": (
                                f"Error: Tool '{inline_name}' does not exist. "
                                f"Please use one of the provided tools (e.g., explore_path, deliver_path)."
                            ),
                        })
                        continue

                    # Task 3.2: Intercept Malformed Arguments
                    schema = TOOL_SCHEMA_MAP.get(inline_name, {})
                    required_params = (
                        schema.get("parameters", {}).get("required", [])
                        or schema.get("required", [])
                    )
                    is_malformed = False
                    if required_params:
                        if not inline_args or not isinstance(inline_args, dict):
                            is_malformed = True
                        elif any(req not in inline_args or inline_args.get(req) is None or inline_args.get(req) == "" for req in required_params):
                            is_malformed = True

                    if is_malformed:
                        logger.warning("AI Planner intercepted inline tool '%s' with missing required arguments: %s", inline_name, inline_args)
                        messages.append(msg)
                        messages.append({
                            "role": "tool",
                            "tool_call_id": "inline_call_0",
                            "name": inline_name,
                            "content": f"Error: You called '{inline_name}' but failed to provide the required arguments. Please emit the tool call again with valid JSON parameters.",
                        })
                        continue

                    inline_tier = get_tool_tier(inline_name, inline_args)
                    inline_tc = ToolCall(
                        tool_name=inline_name,
                        args=inline_args,
                        tier=inline_tier,
                        raw_command=f"{inline_name} {inline_args}",
                    )
                    logger.info("Intercepted inline tool call in message content: %s", inline_name)

                    # Tier 4: Hard-Blocked
                    if inline_tier == SecurityTier.TIER_4_BLOCKED:
                        await db.log_audit(
                            command=inline_tc.raw_command,
                            tier=4,
                            status="BLOCKED",
                            details="Inline tool call blocked by Tier 4 security policy",
                        )
                        messages.append(msg)
                        messages.append({
                            "role": "tool",
                            "tool_call_id": "inline_call_0",
                            "content": "ERROR: Tool execution blocked by Tier 4 security policy.",
                        })
                        continue

                    # Tier 2 or Tier 3: Pause execution for user confirmation/PIN
                    if inline_tier in (SecurityTier.TIER_2_CONFIRM, SecurityTier.TIER_3_PIN):
                        return PlannerResult(
                            completed=False,
                            paused_for_approval=True,
                            paused_tool_call=inline_tc,
                            paused_call_id="inline_call_0",
                            session_messages=messages,
                            step_count=current_step,
                            executed_steps=steps_history,
                        )

                    # Tier 1: Auto-Execute
                    result_str = await execute_tool_locally(inline_name, inline_args)
                    steps_history.append(inline_tc)
                    compressed_out = compress_tool_output(result_str)
                    messages.append(msg)
                    messages.append({
                        "role": "tool",
                        "tool_call_id": "inline_call_0",
                        "content": compressed_out,
                    })

                    # Terminal tool short circuit check
                    self.completed_steps_in_turn += 1
                    if self._should_short_circuit(inline_name, is_analytical):
                        return PlannerResult(
                            completed=True,
                            final_message=result_str,
                            intermediate_message=self.current_intermediate_message,
                            executed_steps=steps_history,
                            session_messages=messages,
                            step_count=current_step,
                        )
                    continue

            # If no structured tool calls and no inline tool call, model gave final text answer
            if not tool_calls:
                # Clean any dangling <think> or XML tags so raw syntax is never leaked to user
                cleaned_final = re.sub(r"<think>[\s\S]*?</think>", "", content, flags=re.IGNORECASE).strip()
                cleaned_final = re.sub(r"<tool_call>[\s\S]*?</tool_call>", "", cleaned_final, flags=re.IGNORECASE).strip()
                cleaned_final = re.sub(r"<function(?:=|\s+name=)[\s\S]*?(?:</function>|$)", "", cleaned_final, flags=re.IGNORECASE).strip()

                return PlannerResult(
                    completed=True,
                    final_message=cleaned_final or "(Action completed)",
                    intermediate_message=self.current_intermediate_message,
                    executed_steps=steps_history,
                    session_messages=messages,
                    step_count=current_step,
                )

            # Task 3.1 & 3.2: Enforce Single Tool Execution in the Backend and queue remaining
            if len(tool_calls) > 1:
                first_fn = tool_calls[0].get("function", {})
                first_name = first_fn.get("name", "unknown")
                print(f"Warning: LLM attempted parallel execution. Truncating to first tool: {first_name}")
                logger.warning("LLM attempted parallel execution (%d tools). Truncating to first tool: %s", len(tool_calls), first_name)

                # Push remaining tool calls into pending_tool_queue
                for remaining_tc in tool_calls[1:]:
                    r_fn = remaining_tc.get("function", {})
                    r_name = r_fn.get("name", "")
                    r_args_raw = r_fn.get("arguments", "{}")
                    try:
                        r_args = json.loads(r_args_raw) if isinstance(r_args_raw, str) else r_args_raw
                    except Exception:
                        r_args = {}
                    r_name = ALIAS_TOOL_MAP.get(r_name.lower(), r_name)
                    r_args = _clean_and_coerce_args(r_args)
                    r_tier = get_tool_tier(r_name, r_args)
                    self.pending_tool_queue.append(
                        ToolCall(
                            tool_name=r_name,
                            args=r_args,
                            tier=r_tier,
                            raw_command=f"{r_name} {r_args}",
                        )
                    )

                tool_calls = [tool_calls[0]]
                msg["tool_calls"] = tool_calls

            # Record assistant message with structured tool calls in history
            messages.append(msg)

            # Process structured tool calls
            for tc in tool_calls:
                call_id = tc.get("id", "call_default")
                fn = tc.get("function", {})
                tool_name = fn.get("name", "")
                raw_args = fn.get("arguments", "{}")

                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                except Exception:
                    args = {}

                # Map alias if needed
                tool_name = ALIAS_TOOL_MAP.get(tool_name.lower(), tool_name)
                args = _clean_and_coerce_args(args)

                # Task 3.1: Intercept unknown tools before permission gate
                if tool_name not in AVAILABLE_TOOL_NAMES:
                    logger.warning("AI Planner intercepted unknown structured tool: %s", tool_name)
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": tool_name,
                        "content": (
                            f"Error: Tool '{tool_name}' does not exist. "
                            f"Please use one of the provided tools (e.g., explore_path, deliver_path)."
                        ),
                    })
                    continue

                # Task 3.2: Intercept Malformed Arguments
                schema = TOOL_SCHEMA_MAP.get(tool_name, {})
                required_params = (
                    schema.get("parameters", {}).get("required", [])
                    or schema.get("required", [])
                )
                is_malformed = False
                if required_params:
                    if not args or not isinstance(args, dict):
                        is_malformed = True
                    elif any(req not in args or args.get(req) is None or args.get(req) == "" for req in required_params):
                        is_malformed = True

                if is_malformed:
                    logger.warning("AI Planner intercepted tool '%s' with missing required arguments: %s", tool_name, args)
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": tool_name,
                        "content": f"Error: You called '{tool_name}' but failed to provide the required arguments. Please emit the tool call again with valid JSON parameters.",
                    })
                    continue

                # Deterministic permission enforcement before running tool
                tier = get_tool_tier(tool_name, args)
                tool_call_obj = ToolCall(
                    tool_name=tool_name,
                    args=args,
                    tier=tier,
                    raw_command=f"{tool_name} {args}",
                )

                # Tier 4: Hard-Blocked
                if tier == SecurityTier.TIER_4_BLOCKED:
                    await db.log_audit(
                        command=tool_call_obj.raw_command,
                        tier=4,
                        status="BLOCKED",
                        details="AI Planner tool call blocked by Tier 4 security policy",
                    )
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": "ERROR: Tool execution blocked by Tier 4 security policy.",
                    })
                    continue

                # Tier 2 or Tier 3: Pause execution for user confirmation/PIN
                if tier in (SecurityTier.TIER_2_CONFIRM, SecurityTier.TIER_3_PIN):
                    return PlannerResult(
                        completed=False,
                        paused_for_approval=True,
                        paused_tool_call=tool_call_obj,
                        paused_call_id=call_id,
                        intermediate_message=self.current_intermediate_message,
                        session_messages=messages,
                        step_count=current_step,
                        executed_steps=steps_history,
                    )

                # Tier 1: Auto-Execute
                result_str = await execute_tool_locally(tool_name, args)
                steps_history.append(tool_call_obj)
                self.completed_steps_in_turn += 1
                compressed_out = compress_tool_output(result_str)
                messages.append({
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": compressed_out,
                })

                # Task 3.3: Terminal tool short circuit
                if self._should_short_circuit(tool_name, is_analytical):
                    return PlannerResult(
                        completed=True,
                        final_message=result_str,
                        intermediate_message=self.current_intermediate_message,
                        executed_steps=steps_history,
                        session_messages=messages,
                        step_count=current_step,
                    )

        # Cap at MAX_PLANNER_STEPS exceeded
        return PlannerResult(
            completed=False,
            final_message=(
                f"⚠️ Plan exceeded the safety maximum of {self.max_steps} steps. "
                "Execution halted to prevent infinite loops."
            ),
            intermediate_message=self.current_intermediate_message,
            executed_steps=steps_history,
            session_messages=messages,
            step_count=current_step,
        )

    async def resume_after_approval(
        self,
        planner_result: PlannerResult,
        approved_tool_output: str,
    ) -> PlannerResult:
        """Resume execution after user confirmed or provided PIN for a paused tool."""
        messages = list(planner_result.session_messages)
        call_id = planner_result.paused_call_id or "call_resumed"

        compressed_out = compress_tool_output(approved_tool_output)
        messages.append({
            "role": "tool",
            "tool_call_id": call_id,
            "content": compressed_out,
        })

        steps_history = list(planner_result.executed_steps)
        paused_tc = planner_result.paused_tool_call
        if paused_tc:
            steps_history.append(paused_tc)

        self.completed_steps_in_turn += 1

        # Find original user prompt
        user_prompt = ""
        for m in planner_result.session_messages:
            if m.get("role") == "user":
                user_prompt = m.get("content", "")
                break

        if not self.is_compound_request and user_prompt:
            self.is_compound_request = bool(re.search(r'\b(and|then|afterwards|also)\b', user_prompt, re.IGNORECASE))

        is_analytical = any(keyword in user_prompt.lower() for keyword in ANALYTICAL_KEYWORDS)

        # Check 1 (Queued Tools Waiting)
        current_intermediate = approved_tool_output
        while self.pending_tool_queue:
            next_tool = self.pending_tool_queue.pop(0)
            tier = get_tool_tier(next_tool.tool_name, next_tool.args)
            next_tool.tier = tier

            if tier == SecurityTier.TIER_4_BLOCKED:
                await db.log_audit(
                    command=next_tool.raw_command,
                    tier=4,
                    status="BLOCKED",
                    details="AI Planner tool call blocked by Tier 4 security policy",
                )
                return PlannerResult(
                    completed=False,
                    final_message="ERROR: Next tool execution blocked by Tier 4 security policy.",
                    intermediate_message=approved_tool_output,
                    executed_steps=steps_history,
                    session_messages=messages,
                    step_count=planner_result.step_count,
                    error="Tier 4 blocked",
                )

            if tier in (SecurityTier.TIER_2_CONFIRM, SecurityTier.TIER_3_PIN):
                next_call_id = f"call_{uuid.uuid4().hex[:8]}"
                messages.append({
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": next_call_id,
                        "type": "function",
                        "function": {
                            "name": next_tool.tool_name,
                            "arguments": json.dumps(next_tool.args),
                        },
                    }],
                })
                return PlannerResult(
                    completed=False,
                    paused_for_approval=True,
                    paused_tool_call=next_tool,
                    paused_call_id=next_call_id,
                    intermediate_message=current_intermediate,
                    session_messages=messages,
                    step_count=planner_result.step_count,
                    executed_steps=steps_history,
                )

            # Tier 1 Auto-Execute
            next_res = await execute_tool_locally(next_tool.tool_name, next_tool.args)
            steps_history.append(next_tool)
            self.completed_steps_in_turn += 1
            current_intermediate = next_res
            next_call_id = f"call_{uuid.uuid4().hex[:8]}"
            messages.append({
                "role": "assistant",
                "content": None,
                "tool_calls": [{
                    "id": next_call_id,
                    "type": "function",
                    "function": {
                        "name": next_tool.tool_name,
                        "arguments": json.dumps(next_tool.args),
                    },
                }],
            })
            messages.append({
                "role": "tool",
                "tool_call_id": next_call_id,
                "content": compress_tool_output(next_res),
            })
            if self._should_short_circuit(next_tool.tool_name, is_analytical):
                return PlannerResult(
                    completed=True,
                    final_message=next_res,
                    intermediate_message=approved_tool_output if current_intermediate != approved_tool_output else None,
                    executed_steps=steps_history,
                    session_messages=messages,
                    step_count=planner_result.step_count,
                )

        # Check 2 (Sequential LLM Continuation for Compound Prompts)
        tool_name = paused_tc.tool_name if paused_tc else ""
        if self._should_short_circuit(tool_name, is_analytical):
            return PlannerResult(
                completed=True,
                final_message=approved_tool_output,
                executed_steps=steps_history,
                session_messages=messages,
                step_count=planner_result.step_count,
            )

        # Task 3.2: Continuation nudge for compound prompts
        if not self.pending_tool_queue and self.is_compound_request and self.completed_steps_in_turn < 2:
            messages.append({
                "role": "system",
                "content": (
                    "Step 1 is complete. You MUST now emit the tool call for the remaining "
                    "action in the user's request. Do not reply with plain text."
                ),
            })

        return await self.plan_and_execute(
            user_prompt="",
            session_messages=messages,
            executed_steps=steps_history,
            step_count=planner_result.step_count,
            intermediate_message=approved_tool_output,
        )
