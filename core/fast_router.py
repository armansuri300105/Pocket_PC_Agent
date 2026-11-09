"""Fast deterministic command router.

Routes built-in commands and user-taught shortcuts directly to structured ToolCall
objects in under 5ms without calling any LLM.
Returns None for complex, ambiguous, or multi-step requests requiring the AI planner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional, Union

try:
    import emoji
except ImportError:
    emoji = None


def strip_emojis(text: str) -> str:
    """Strip emojis and leading symbols/whitespace from text."""
    if not text:
        return ""
    if emoji is not None:
        cleaned = emoji.replace_emoji(text, replace="").strip()
    else:
        cleaned = text.strip()
    return re.sub(r"^[^\w\s/]+", "", cleaned).strip()

from core import db
from core.permissions import SecurityTier, get_tool_tier


@dataclass
class ToolCall:
    """Structured representation of a routed tool execution."""
    tool_name: str
    args: Dict[str, Any] = field(default_factory=dict)
    tier: SecurityTier = SecurityTier.TIER_1_AUTO
    raw_command: str = ""


# Compiled intent matchers for instant deterministic routing (< 1ms)
RE_BATTERY = re.compile(
    r"^(?:(?:can\s+you\s+|could\s+you\s+|please\s+)?)"
    r"(?:(?:what(?:'s|\s+is)|how\s+is|check|show|get|display|tell\s+me)\s+(?:the\s+|my\s+)?)?"
    r"(?:battery|power|charge|charging|battery\s+(?:status|percentage|level|percent|life))"
    r"(?:\s+(?:status|percentage|level|percent|life|now))?"
    r"(?:\s+(?:of|for)\s+(?:the\s+|my\s+)?(?:pc|laptop|computer|machine))?"
    r"(?:\s+please)?$",
    re.IGNORECASE,
)
RE_VITALS = re.compile(
    r"^(?:(?:can\s+you\s+|could\s+you\s+|please\s+)?)"
    r"(?:(?:what(?:'s|\s+is)|how\s+is|check|show|get|display|tell\s+me)\s+(?:the\s+|my\s+)?)?"
    r"(?:system\s+info|system\s+vitals|system\s+status|system\s+health|vitals|pc\s+info|pc\s+status|pc\s+specs|laptop\s+status|status|specs|cpu|ram|disk|/status|/vitals)"
    r"(?:\s+(?:of|for)\s+(?:the\s+|my\s+)?(?:pc|laptop|system|computer|machine))?"
    r"(?:\s+please)?$|"
    r"^(?:how\s+is\s+(?:the\s+|my\s+)?(?:pc|laptop|computer|system))(?:\s+doing)?(?:\s+please)?$",
    re.IGNORECASE,
)
RE_SCREENSHOT = re.compile(
    r"^(?:(?:can\s+you\s+|could\s+you\s+|please\s+|kindly\s+)?)"
    r"(?:(?:give(?:\s+me)?|send(?:\s+me)?|take|capture|get|grab|show|snap)\s+)?"
    r"(?:a\s+|an\s+|the\s+|my\s+)?"
    r"(?:(?:pc|laptop|desktop|screen)\s+)?"
    r"(?:screenshot|screen\s*shot|screen\s*capture|screen\s*grab|screen|shot|/?screenshot)"
    r"(?:\s+(?:of|from)\s+(?:the\s+|my\s+)?(?:pc|laptop|screen|desktop|computer|machine))?"
    r"(?:\s+please)?$",
    re.IGNORECASE,
)
RE_UNDO = re.compile(
    r"^(?:(?:can\s+you\s+|could\s+you\s+|please\s+)?)"
    r"(?:undo|revert|/undo|undo\s+(?:last|action|last\s+action|that)|restore\s+last\s+(?:file|action))"
    r"(?:\s+please)?$",
    re.IGNORECASE,
)
RE_STOP = re.compile(r"^(?:(?:please\s+)?(?:stop|cancel|abort|/stop|/cancel))$", re.IGNORECASE)
RE_REBOOT = re.compile(r"^(?:(?:please\s+)?(?:reboot|restart\s+(?:laptop|pc|computer|system)|/reboot))$", re.IGNORECASE)
RE_SHUTDOWN = re.compile(r"^(?:(?:please\s+)?(?:shutdown|power\s+off|shut\s+down|/shutdown))$", re.IGNORECASE)

RE_FIND = re.compile(r"^(?:(?:can\s+you\s+|could\s+you\s+|please\s+)?)(?:find|search(?:\s+for)?|locate|where\s+is|/find)\s+(.+)$", re.IGNORECASE)
RE_DELETE = re.compile(r"^(?:(?:can\s+you\s+|could\s+you\s+|please\s+)?)(?:delete|remove|rm|/delete)\s+(.+)$", re.IGNORECASE)
RE_MOVE = re.compile(r"^(?:(?:can\s+you\s+|could\s+you\s+|please\s+)?)(?:move|mv)\s+(.+?)\s+(?:to\s+)?(.+)$", re.IGNORECASE)
RE_ZIP = re.compile(r"^(?:(?:can\s+you\s+|could\s+you\s+|please\s+)?)(?:zip|compress|archive|/zip)\s+(.+)$", re.IGNORECASE)
RE_KILL = re.compile(r"^(?:(?:can\s+you\s+|could\s+you\s+|please\s+)?)(?:kill|terminate)\s+(?:process\s+)?(.+)$", re.IGNORECASE)
RE_RUN = re.compile(r"^(?:(?:can\s+you\s+|could\s+you\s+|please\s+)?)(?:run|exec|sh|bash|cmd|shell|/run|/exec)\s+(.+)$", re.IGNORECASE)

# Phase 5: Dev Services, Cloudflare Quick Tunnels, Caffeinate
RE_SERVICES = re.compile(
    r"^(?:(?:can\s+you\s+|could\s+you\s+|please\s+)?)"
    r"(?:(?:what\s+services\s+are\s+running|list\s+(?:running\s+)?services|show\s+(?:running\s+)?services|check\s+(?:running\s+)?services|running\s+services|services|ps|/services))"
    r"(?:\s+please)?$",
    re.IGNORECASE,
)
RE_START_SERVICE = re.compile(
    r"^(?:(?:can\s+you\s+|could\s+you\s+|please\s+)?)"
    r"(?:/start_service|start_service|start|run|launch)\s+"
    r"(?:the\s+)?"
    r"(?:(?:project|service|app)\s+)?"
    r"(?:(?:present|located)\s+in\s+)?"
    r"(.+?)$",
    re.IGNORECASE,
)
RE_STOP_SERVICE = re.compile(
    r"^(?:(?:can\s+you\s+|could\s+you\s+|please\s+)?)"
    r"(?:/stop_service|stop_service|stop)\s+"
    r"(?:the\s+)?"
    r"(?:(?:project|service|app)\s+)?"
    r"(?:(?:present|located)\s+in\s+)?"
    r"(.+?)$",
    re.IGNORECASE,
)
RE_LOGS_SERVICE = re.compile(r"^(?:(?:can\s+you\s+|could\s+you\s+|please\s+)?)(?:logs|service\s+logs|/logs)\s+(.+)$", re.IGNORECASE)
RE_TUNNEL = re.compile(
    r"^(?:(?:can\s+you\s+|could\s+you\s+|please\s+)?)"
    r"(?:/tunnel|tunnel|expose|share)\s+(?:port\s+)?(\d{2,5})$",
    re.IGNORECASE,
)
RE_CAFFEINATE = re.compile(
    r"^(?:(?:can\s+you\s+|could\s+you\s+|please\s+)?)"
    r"(?:(?:/caffeinate|caffeinate)(?:\s+(on|off|status))?|"
    r"(?:keep\s+awake|prevent\s+sleep|dont\s+sleep|don't\s+sleep)(?:\s+(on|off|status))?)$",
    re.IGNORECASE,
)

# Detect multi-step conjunctions that must go to the AI planner
RE_MULTI_STEP = re.compile(r"\b(?:then|and\s+then|after\s+that|and\s+also)\b", re.IGNORECASE)


async def route_command(
    message: str,
    db_path: Optional[Union[str, Path]] = None,
) -> Optional[ToolCall]:
    """Route user message deterministically to a ToolCall.

    1. Checks SQLite shortcuts table first (e.g. 'shot' -> 'screenshot').
    2. Pattern-matches against built-in commands without LLM invocation.
    3. Evaluates mandatory SecurityTier via core.permissions.
    4. Returns None for multi-step or complex queries requiring AI planning.
    """
    if not message or not message.strip():
        return None

    raw_text = message.strip()
    clean_text = strip_emojis(raw_text)
    if not clean_text:
        return None

    # Step 1: Check SQLite shortcuts table (check clean_text first, then raw_text)
    shortcut_target = await db.get_shortcut(clean_text, db_path=db_path) or await db.get_shortcut(raw_text, db_path=db_path)
    if shortcut_target:
        text = strip_emojis(shortcut_target.strip())
    else:
        text = clean_text

    # If the request is a multi-step chain, route to AI planner
    if RE_MULTI_STEP.search(text):
        return None

    # Step 2: Deterministic pattern matching
    tool_name: Optional[str] = None
    tool_args: Dict[str, Any] = {}

    # Battery
    if RE_BATTERY.match(text):
        tool_name = "get_system_vitals"
        tool_args = {"component": "battery"}

    # System Info / Vitals
    elif RE_VITALS.match(text):
        tool_name = "get_system_vitals"
        tool_args = {}

    # Screenshot
    elif RE_SCREENSHOT.match(text):
        tool_name = "capture_screenshot"
        tool_args = {}

    # Undo
    elif RE_UNDO.match(text):
        tool_name = "undo_last_action"
        tool_args = {}

    # Stop
    elif RE_STOP.match(text):
        tool_name = "stop_service"
        tool_args = {}

    # Reboot
    elif RE_REBOOT.match(text):
        tool_name = "reboot_system"
        tool_args = {}

    # Shutdown
    elif RE_SHUTDOWN.match(text):
        tool_name = "shutdown_system"
        tool_args = {}

    # Find Files
    elif (m := RE_FIND.match(text)):
        query = m.group(1).strip()
        tool_name = "find_files"
        tool_args = {"query": query}

    # Delete File
    elif (m := RE_DELETE.match(text)):
        target = m.group(1).strip()
        cleaned = re.sub(
            r"^(?:the\s+)?(?:file|folder|directory)\s+(?:named|called|at|in|present\s+in)?\s*",
            "",
            target,
            flags=re.IGNORECASE,
        ).strip().strip("'\"")
        tool_name = "safe_delete"
        tool_args = {"target_path": cleaned if cleaned else target}

    # Move File
    elif (m := RE_MOVE.match(text)):
        src = m.group(1).strip()
        dst = m.group(2).strip()
        cleaned_src = re.sub(
            r"^(?:the\s+)?(?:file|folder|directory)\s+(?:named|called|at|in|present\s+in)?\s*",
            "",
            src,
            flags=re.IGNORECASE,
        ).strip().strip("'\"")
        cleaned_dst = re.sub(
            r"^(?:the\s+)?(?:file|folder|directory)\s+(?:named|called|at|in|present\s+in|to)?\s*",
            "",
            dst,
            flags=re.IGNORECASE,
        ).strip().strip("'\"")
        tool_name = "safe_move"
        tool_args = {
            "src": cleaned_src if cleaned_src else src,
            "dst": cleaned_dst if cleaned_dst else dst,
        }

    # Zip Folder / File
    elif (m := RE_ZIP.match(text)):
        path = m.group(1).strip()
        tool_name = "zip_and_prepare"
        tool_args = {"path": path}

    # Kill Process
    elif (m := RE_KILL.match(text)):
        proc_target = m.group(1).strip()
        pid_m = re.search(r"\b(?:pid\s*)?(\d+)\b", proc_target, re.IGNORECASE)
        if pid_m:
            tool_args = {"pid": int(pid_m.group(1))}
        else:
            tool_args = {"target": proc_target}
        tool_name = "kill_process"

    # Run Shell Command
    elif (m := RE_RUN.match(text)) and not re.search(r"\b(?:project|projects|app|service|services|server|backend|frontend)\b", m.group(1), re.IGNORECASE):
        cmd = m.group(1).strip()
        tool_name = "run_shell"
        tool_args = {"command": cmd}

    # Running Dev Services
    elif RE_SERVICES.match(text):
        tool_name = "list_running_services"
        tool_args = {}

    # Start Named Service / Detected Project
    elif (m := RE_START_SERVICE.match(text.rstrip("."))):
        raw_target = m.group(1).strip()
        # Invariant: Do not match if the captured target still contains a conjunction like " and "
        if re.search(r"\b(?:and\s+then|then|and|also|after\s+that)\b", raw_target, re.IGNORECASE):
            return None

        # Check for component phrasing:
        # 1. "(backend|frontend|...) of <project>"
        # 2. "<project> (backend|frontend|...)"
        comp_m1 = re.match(
            r"^(?:the\s+)?(backend|frontend|server|client|docker|api|ui)\s+(?:of\s+)(.+)$",
            raw_target,
            re.IGNORECASE,
        )
        comp_m2 = re.match(
            r"^(.+?)\s+(backend|frontend|server|client|docker|api|ui)$",
            raw_target,
            re.IGNORECASE,
        )
        if comp_m1:
            component = comp_m1.group(1).lower()
            project = comp_m1.group(2).strip()
        elif comp_m2:
            project = comp_m2.group(1).strip()
            component = comp_m2.group(2).lower()
        else:
            project = raw_target
            component = None

        project = re.sub(
            r"^(?:the\s+)?(?:(?:project|service|app)\s+)?(?:(?:present|located)\s+in\s+)?",
            "",
            project,
            flags=re.IGNORECASE,
        ).strip()
        project = project.rstrip(".")

        if not project:
            return None

        tool_name = "start_named_service"
        tool_args = {"target": project, "service_name": project}
        if component:
            tool_args["component"] = component

    # Stop Named Service / Kill by PID
    elif (m := RE_STOP_SERVICE.match(text.rstrip("."))):
        raw_target = m.group(1).strip()
        # Invariant: Do not match if captured target contains a conjunction
        if re.search(r"\b(?:and\s+then|then|and|also|after\s+that)\b", raw_target, re.IGNORECASE):
            return None

        svc = re.sub(
            r"^(?:the\s+)?(?:(?:project|service|app)\s+)?(?:(?:present|located)\s+in\s+)?",
            "",
            raw_target,
            flags=re.IGNORECASE,
        ).strip().rstrip(".")

        if not svc:
            return None

        pid_match = re.search(r"\b(?:pid|process\s*(?:id)?)\s*[:=]?\s*(\d+)\b", svc, re.IGNORECASE) or re.match(r"^(\d+)$", svc)
        if pid_match:
            tool_name = "kill_process"
            tool_args = {"pid": int(pid_match.group(1))}
        else:
            tool_name = "stop_named_service"
            tool_args = {"target": svc, "service_name": svc}

    # Service Logs
    elif (m := RE_LOGS_SERVICE.match(text)):
        svc = m.group(1).strip()
        tool_name = "get_service_logs"
        tool_args = {"service_name": svc}

    # Cloudflare Quick Tunnel
    elif (m := RE_TUNNEL.match(text)):
        port_num = int(m.group(1))
        tool_name = "expose_port_tunnel"
        tool_args = {"port": port_num}

    # Caffeinate Sleep Prevention
    elif (m := RE_CAFFEINATE.match(text)):
        arg = (m.group(1) or "").lower()
        if arg in ("on", "off"):
            tool_name = "caffeinate_toggle"
            tool_args = {"state": arg}
        else:
            tool_name = "caffeinate_status"
            tool_args = {}

    if tool_name is None:
        return None

    # Step 3: Compute deterministic security tier
    tier = get_tool_tier(tool_name, tool_args)

    return ToolCall(
        tool_name=tool_name,
        args=tool_args,
        tier=tier,
        raw_command=raw_text,
    )


# Conjunction split pattern and context pronoun regex
RE_CONJUNCTION_SPLIT = re.compile(
    r"\s+\b(?:and\s+then|then|after\s+that|and\s+also|and)\b\s+",
    re.IGNORECASE,
)
RE_CONTEXT_REF = re.compile(r"\b(?:it|them|this|that|those|these)\b", re.IGNORECASE)
RE_PRONOUN_COMMAND = re.compile(
    r"\b(?:send|zip|delete|move|download|fetch|get|pack)\s+(?:it|them|that|this|those|these)\b",
    re.IGNORECASE,
)


async def route_command_chain(
    raw_text: str,
    db_path: Optional[Union[str, Path]] = None,
) -> Optional[List[ToolCall]]:
    """Deterministically route a conjunction chain into multiple ToolCalls.

    Splits on conjunctions ('and then', 'then', 'after that', 'and also').
    Returns None if:
    - Any clause cannot be deterministically routed
    - Any clause references contextual pronouns ('send it', 'zip them', etc.)
    - raw_text is empty
    """
    if not raw_text or not raw_text.strip():
        return None

    clean_text = strip_emojis(raw_text.strip())
    if not clean_text:
        return None

    clauses = [c.strip() for c in RE_CONJUNCTION_SPLIT.split(clean_text) if c.strip()]

    if len(clauses) <= 1:
        single = await route_command(clean_text, db_path=db_path)
        return [single] if single else None

    tool_calls: List[ToolCall] = []
    for clause in clauses:
        # Contextual pronoun check in phrasing
        if RE_PRONOUN_COMMAND.search(clause):
            return None

        tc = await route_command(clause, db_path=db_path)
        if tc is None:
            return None

        # Context reference in parsed tool arguments
        for val in tc.args.values():
            if isinstance(val, str) and RE_CONTEXT_REF.fullmatch(val.strip().lower()):
                return None

        tool_calls.append(tc)

    return tool_calls

