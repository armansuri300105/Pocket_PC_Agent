"""Deterministic Project Inspector and Stack Detector for PocketPC Agent.

Detects project frameworks, entrypoints, virtual environments, and ports across
ALLOWED_DIRS in pure Python without LLM token usage (< 15ms).

Supported Tech Stacks:
1. Python / FastAPI / Flask / Django (venv + main.py / app.py)
2. React (Vite) / Next.js (package.json + vite.config / next.config)
3. Node.js Backends (Express / NestJS / Fastify)
4. Docker Compose (docker-compose.yml / compose.yaml)
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

from core.config import get_settings
from core.sandbox import is_path_allowed

logger = logging.getLogger(__name__)

# Directory names to skip when scanning projects
IGNORED_DIRS = {
    ".git",
    ".pytest_cache",
    ".undo_storage",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".vscode",
    ".idea",
}


@dataclass
class ServiceSpec:
    """Discovered service run configuration."""
    project_name: str
    component: str             # "backend", "frontend", "docker", "root"
    stack: str                 # "FastAPI / Python", "React (Vite)", "Next.js", "Node.js", "Docker Compose"
    cwd: Path
    cmd: List[str]
    port: Optional[int] = None
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_name": self.project_name,
            "component": self.component,
            "stack": self.stack,
            "cwd": str(self.cwd),
            "cmd": self.cmd,
            "port": self.port,
            "description": self.description,
        }


def find_project_dir(name: str, allowed_dirs: Optional[List[Union[str, Path]]] = None) -> Optional[Path]:
    """Locate the root directory of a project by name inside allowed directories.
    
    Performs case-insensitive and normalized exact/fuzzy matching.
    """
    clean = name.strip().lower().replace("-", "_").replace(" ", "_")
    if not clean:
        return None

    search_roots = (
        [Path(d).resolve() for d in allowed_dirs]
        if allowed_dirs is not None
        else get_settings().ALLOWED_DIRS
    )

    # 1. Direct path check
    direct = Path(name).resolve()
    if direct.is_dir() and is_path_allowed(direct, allowed_dirs=search_roots):
        return direct

    # 2. Check immediate children and grandchildren of allowed roots
    candidates: List[Path] = []
    for root in search_roots:
        if not root.is_dir():
            continue

        # Check immediate directory name
        if root.name.lower().replace("-", "_").replace(" ", "_") == clean:
            return root

        # Walk up to depth 3
        try:
            for p in root.iterdir():
                if not p.is_dir() or p.name in IGNORED_DIRS or p.name.startswith("."):
                    continue

                p_norm = p.name.lower().replace("-", "_").replace(" ", "_")
                if p_norm == clean:
                    return p.resolve()

                # Check 1 level deeper (e.g. Projects 2.0 / Trading_agent)
                try:
                    for sub in p.iterdir():
                        if not sub.is_dir() or sub.name in IGNORED_DIRS or sub.name.startswith("."):
                            continue
                        sub_norm = sub.name.lower().replace("-", "_").replace(" ", "_")
                        if sub_norm == clean:
                            return sub.resolve()
                        if clean in sub_norm:
                            candidates.append(sub.resolve())
                except OSError:
                    continue

                if clean in p_norm:
                    candidates.append(p.resolve())
        except OSError:
            continue

    if candidates:
        return candidates[0]

    # 3. Fallback to SmartFileResolver
    try:
        from core.smart_resolver import SmartFileResolver
        resolved = SmartFileResolver.get_instance().resolve(name, allowed_dirs=search_roots)
        if resolved.is_dir() and is_path_allowed(resolved, allowed_dirs=search_roots):
            return resolved
        elif resolved.is_file() and is_path_allowed(resolved.parent, allowed_dirs=search_roots):
            return resolved.parent
    except Exception:
        pass

    return None


def find_venv_python(directory: Path) -> Path:
    """Find the virtual environment Python interpreter for a directory.
    
    Checks directory, parent, and grandparent for .venv / venv / env.
    Falls back to sys.executable if no local venv is found.
    """
    check_dirs = [directory, directory.parent]
    if directory.parent != directory.parent.parent:
        check_dirs.append(directory.parent.parent)

    venv_names = [".venv", "venv", "env"]

    for d in check_dirs:
        for vname in venv_names:
            vdir = d / vname
            if vdir.is_dir():
                py = vdir / "Scripts" / "python.exe" if os.name == "nt" else vdir / "bin" / "python"
                if py.is_file():
                    return py.resolve()

    return Path(sys.executable).resolve()


def inspect_python_service(
    directory: Path,
    project_name: str,
    component_name: str = "backend",
) -> Optional[ServiceSpec]:
    """Detect Python FastAPI / Flask / script service in a directory."""
    if not directory.is_dir():
        return None

    entrypoints = ["main.py", "app.py", "server.py", "run.py", "api.py"]
    chosen_entry: Optional[Path] = None

    for ep in entrypoints:
        candidate = directory / ep
        if candidate.is_file():
            chosen_entry = candidate
            break

    if not chosen_entry:
        return None

    # Detect stack & port
    content = ""
    try:
        content = chosen_entry.read_text(encoding="utf-8", errors="ignore")[:4000]
    except Exception:
        pass

    stack = "Python Service"
    if "fastapi" in content.lower() or "uvicorn" in content.lower():
        stack = "FastAPI / Python"
    elif "flask" in content.lower():
        stack = "Flask / Python"
    elif "django" in content.lower():
        stack = "Django / Python"

    # Search for port declaration (e.g. port=8000, PORT=8000)
    port: Optional[int] = 8000 if stack == "FastAPI / Python" else (5000 if stack == "Flask / Python" else 8000)
    port_match = re.search(r"\bport\s*=\s*(\d{4,5})\b", content, re.IGNORECASE)
    if port_match:
        try:
            port = int(port_match.group(1))
        except ValueError:
            pass

    py_exe = find_venv_python(directory)

    return ServiceSpec(
        project_name=project_name,
        component=component_name,
        stack=stack,
        cwd=directory,
        cmd=[str(py_exe), chosen_entry.name],
        port=port,
        description=f"{project_name} {component_name} ({stack})",
    )


def inspect_node_service(
    directory: Path,
    project_name: str,
    component_name: str = "frontend",
) -> Optional[ServiceSpec]:
    """Detect Node.js / React (Vite) / Next.js service in a directory."""
    pkg_file = directory / "package.json"
    if not pkg_file.is_file():
        return None

    try:
        pkg_data = json.loads(pkg_file.read_text(encoding="utf-8"))
    except Exception:
        return None

    scripts = pkg_data.get("scripts", {})
    chosen_script: Optional[str] = None
    if "dev" in scripts:
        chosen_script = "dev"
    elif "start" in scripts:
        chosen_script = "start"
    elif "start:dev" in scripts:
        chosen_script = "start:dev"
    else:
        return None

    # Detect Framework
    is_vite = any((directory / f).exists() for f in ["vite.config.js", "vite.config.ts", "vite.config.mjs"])
    is_next = any((directory / f).exists() for f in ["next.config.js", "next.config.mjs", "next.config.ts"])

    if is_vite:
        stack = "React (Vite)"
        port = 5173
    elif is_next:
        stack = "Next.js"
        port = 3000
    elif component_name == "backend" or "express" in pkg_data.get("dependencies", {}) or "nest" in pkg_data.get("dependencies", {}):
        stack = "Node.js Backend"
        port = 3000
    else:
        stack = "Node.js Application"
        port = 3000

    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    cmd = [npm_cmd, "run", chosen_script]
    if is_vite:
        cmd.extend(["--", "--host"])

    return ServiceSpec(
        project_name=project_name,
        component=component_name,
        stack=stack,
        cwd=directory,
        cmd=cmd,
        port=port,
        description=f"{project_name} {component_name} ({stack})",
    )


def inspect_docker_service(directory: Path, project_name: str) -> Optional[ServiceSpec]:
    """Detect Docker Compose service in a directory."""
    compose_names = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]
    for cname in compose_names:
        cfile = directory / cname
        if cfile.is_file():
            # Try to parse first exposed port
            port = None
            try:
                content = cfile.read_text(encoding="utf-8", errors="ignore")
                pm = re.search(r'["\']?(\d{4,5}):\d{4,5}["\']?', content)
                if pm:
                    port = int(pm.group(1))
            except Exception:
                pass

            return ServiceSpec(
                project_name=project_name,
                component="docker",
                stack="Docker Compose",
                cwd=directory,
                cmd=["docker", "compose", "up", "-d"],
                port=port,
                description=f"{project_name} Docker Compose Services",
            )
    return None


def inspect_all_components(project_dir: Path) -> Dict[str, ServiceSpec]:
    """Inspect a project folder and all its subdirectories for runnable components."""
    results: Dict[str, ServiceSpec] = {}
    pname = project_dir.name

    # 1. Check root directory directly
    root_docker = inspect_docker_service(project_dir, pname)
    if root_docker:
        results["docker"] = root_docker

    root_py = inspect_python_service(project_dir, pname, "root")
    if root_py:
        results["root"] = root_py

    root_node = inspect_node_service(project_dir, pname, "root")
    if root_node and "root" not in results:
        results["root"] = root_node

    # 2. Check candidate subdirectories (e.g. backend, frontend, server, client, or nested folders)
    candidate_subdirs: List[Tuple[str, Path]] = []
    try:
        for child in project_dir.iterdir():
            if not child.is_dir() or child.name in IGNORED_DIRS or child.name.startswith("."):
                continue

            low = child.name.lower()
            if low in ("backend", "server", "api"):
                candidate_subdirs.append(("backend", child))
            elif low in ("frontend", "client", "web", "ui"):
                candidate_subdirs.append(("frontend", child))
            else:
                # Check 1 level deeper (e.g. autonomous-strategist/backend)
                try:
                    for sub in child.iterdir():
                        if not sub.is_dir() or sub.name in IGNORED_DIRS or sub.name.startswith("."):
                            continue
                        sub_low = sub.name.lower()
                        if sub_low in ("backend", "server", "api"):
                            candidate_subdirs.append(("backend", sub))
                        elif sub_low in ("frontend", "client", "web", "ui"):
                            candidate_subdirs.append(("frontend", sub))
                except OSError:
                    pass
    except OSError:
        pass

    for comp_type, cdir in candidate_subdirs:
        if comp_type == "backend":
            spec = inspect_python_service(cdir, pname, "backend") or inspect_node_service(cdir, pname, "backend")
            if spec:
                results["backend"] = spec
        elif comp_type == "frontend":
            spec = inspect_node_service(cdir, pname, "frontend")
            if spec:
                results["frontend"] = spec

    return results


def inspect_project(directory: Union[str, Path]) -> Dict[str, ServiceSpec]:
    """Auto-detect tech stack and return runnable service components for a project directory."""
    path = Path(directory).resolve()
    return inspect_all_components(path)


def resolve_service_to_start(
    target_name: str,
    component: Optional[str] = None,
    allowed_dirs: Optional[List[Union[str, Path]]] = None,
) -> Tuple[Optional[ServiceSpec], List[ServiceSpec], str]:
    """Resolve a target name and component into an exact executable ServiceSpec.
    
    Returns:
    (selected_spec, available_specs, message)
    """
    proj_dir = find_project_dir(target_name, allowed_dirs=allowed_dirs)
    if not proj_dir:
        return (None, [], f"Could not find project directory matching '{target_name}' in allowed paths.")

    components = inspect_all_components(proj_dir)
    if not components:
        return (None, [], f"Project '{proj_dir.name}' found at `{proj_dir}`, but no runnable tech stack (FastAPI, Node, React, Docker) was detected.")

    available = list(components.values())

    # If specific component requested (e.g. "backend", "frontend", "docker")
    if component:
        comp_clean = component.strip().lower()
        if comp_clean in components:
            return (components[comp_clean], available, "Component matched successfully.")
        # Check partial match
        for k, spec in components.items():
            if comp_clean in k or comp_clean in spec.stack.lower():
                return (spec, available, "Component matched partially.")

    # If only 1 component exists, pick it
    if len(components) == 1:
        return (available[0], available, "Single runnable component detected.")

    # Default priority: backend > root > docker > frontend
    for priority in ("backend", "root", "docker", "frontend"):
        if priority in components:
            return (components[priority], available, f"Multiple components detected. Selected default '{priority}'.")

    return (available[0], available, "Selected first available component.")
