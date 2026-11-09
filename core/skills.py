"""Saved Skills Manager for PocketPC Agent.

Enables saving successful multi-step tool chains into SQLite as reusable skills,
listing them via /skills, and removing them via /forget <skill>.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from core import db
from core.fast_router import ToolCall
from core.permissions import SecurityTier, get_tool_tier


@dataclass
class Skill:
    """Representation of a saved multi-step tool workflow."""
    name: str
    description: str
    steps: List[Dict[str, Any]]
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


async def save_skill(
    name: str,
    steps: List[Dict[str, Any]],
    description: str = "",
    db_path: Optional[Union[str, Path]] = None,
) -> Skill:
    """Save a list of tool steps as a named skill."""
    clean_name = name.strip().lower()
    if not clean_name:
        raise ValueError("Skill name cannot be empty.")

    steps_json = json.dumps(steps)
    await db.save_skill_record(
        name=clean_name,
        description=description.strip() or f"Custom workflow '{clean_name}'",
        steps_json=steps_json,
        db_path=db_path,
    )

    record = await db.get_skill_record(clean_name, db_path=db_path)
    return Skill(
        name=clean_name,
        description=record["description"] if record else description,
        steps=steps,
        created_at=record["created_at"] if record else "",
    )


async def get_skill(
    name: str,
    db_path: Optional[Union[str, Path]] = None,
) -> Optional[Skill]:
    """Retrieve a saved skill by name."""
    clean_name = name.strip().lower()
    record = await db.get_skill_record(clean_name, db_path=db_path)
    if not record:
        return None

    try:
        steps = json.loads(record["steps_json"])
    except Exception:
        steps = []

    return Skill(
        name=record["name"],
        description=record["description"],
        steps=steps,
        created_at=record["created_at"],
    )


async def list_skills(
    db_path: Optional[Union[str, Path]] = None,
) -> List[Skill]:
    """List all saved skills."""
    records = await db.list_skill_records(db_path=db_path)
    skills = []
    for r in records:
        try:
            steps = json.loads(r["steps_json"])
        except Exception:
            steps = []
        skills.append(
            Skill(
                name=r["name"],
                description=r["description"],
                steps=steps,
                created_at=r["created_at"],
            )
        )
    return skills


async def delete_skill(
    name: str,
    db_path: Optional[Union[str, Path]] = None,
) -> bool:
    """Delete a saved skill by name."""
    clean_name = name.strip().lower()
    return await db.delete_skill_record(clean_name, db_path=db_path)


def steps_to_tool_calls(skill: Skill) -> List[ToolCall]:
    """Convert skill steps into a list of ToolCalls with deterministic tiers computed."""
    tool_calls: List[ToolCall] = []
    for step in skill.steps:
        tool_name = step.get("tool_name", "")
        args = step.get("args", {})
        tier = get_tool_tier(tool_name, args)
        tool_calls.append(
            ToolCall(
                tool_name=tool_name,
                args=args,
                tier=tier,
                raw_command=f"skill:{skill.name} -> {tool_name}",
            )
        )
    return tool_calls
