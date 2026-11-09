"""Smart File and Directory Resolver for PocketPC Agent.

Indexes allowed directories in background and fuzzy-matches paths accurately
using rapidfuzz while strictly enforcing directory jail invariants.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from rapidfuzz import fuzz, process

from core.config import get_settings

logger = logging.getLogger(__name__)

# Common folders and files to ignore during indexing
IGNORED_NAMES = {
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


def normalize_drive_alias(path_str: str) -> str:
    """Normalize user drive shorthand (e.g. D_drive\\foo or d:\\foo to C:\\D_Drive\\foo if mapped)."""
    s = path_str.strip().strip('"').strip("'")
    if re.match(r"^(?:d_drive|d:)[\\/]", s, re.IGNORECASE):
        candidate = Path("C:/D_Drive") / re.sub(r"^(?:d_drive|d:)[\\/]", "", s, flags=re.IGNORECASE)
        if candidate.exists():
            return str(candidate)
    return s


class SmartFileResolver:
    """Singleton resolver that indexes allowed directories and fuzzy-matches paths accurately."""

    _instance: Optional[SmartFileResolver] = None

    def __new__(cls, *args: Any, **kwargs: Any) -> SmartFileResolver:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_resolver()
        return cls._instance

    @classmethod
    def get_instance(cls) -> SmartFileResolver:
        """Return the singleton instance of SmartFileResolver."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _init_resolver(self) -> None:
        """Initialize empty indices."""
        self.folder_index: Dict[str, Path] = {}
        self.file_index: Dict[str, Path] = {}
        self._last_indexed_dirs: List[Path] = []
        self._indexed: bool = False

    def clear_index(self) -> None:
        """Clear the cached index (useful for isolated tests)."""
        self.folder_index.clear()
        self.file_index.clear()
        self._last_indexed_dirs.clear()
        self._indexed = False

    async def build_index(
        self,
        allowed_dirs: Optional[List[Union[str, Path]]] = None,
        max_depth: int = 4,
    ) -> None:
        """Asynchronously build folder and file index from allowed directories without blocking loop."""
        await asyncio.to_thread(self._build_index_sync, allowed_dirs, max_depth)

    def _build_index_sync(
        self,
        allowed_dirs: Optional[List[Union[str, Path]]] = None,
        max_depth: int = 4,
    ) -> None:
        """Synchronously scan allowed directories up to max_depth and build lookup indices."""
        if allowed_dirs is not None:
            dirs_to_walk = [Path(d).resolve() for d in allowed_dirs]
        else:
            dirs_to_walk = [Path(d).resolve() for d in get_settings().ALLOWED_DIRS]

        new_folder_index: Dict[str, Path] = {}
        new_file_index: Dict[str, Path] = {}

        for base_dir in dirs_to_walk:
            if not base_dir.exists():
                continue

            # 1. Register base directory itself at depth 0 so roots are never overwritten
            base_resolved = base_dir.resolve()
            base_name = base_resolved.name
            if base_name:
                base_lower = base_name.lower()
                new_folder_index[base_lower] = base_resolved
                new_folder_index[base_lower.replace("_", " ")] = base_resolved
                new_folder_index[base_lower.replace(" ", "_")] = base_resolved
                if base_lower in ("d_drive", "d-drive", "d:"):
                    new_folder_index["d_drive"] = base_resolved
                    new_folder_index["d:"] = base_resolved
                    new_folder_index["d drive"] = base_resolved
            elif base_resolved.drive:
                drive_key = base_resolved.drive.lower().replace(":", "_drive")
                new_folder_index[drive_key] = base_resolved
                new_folder_index[base_resolved.drive.lower()] = base_resolved
                new_folder_index["d_drive"] = base_resolved

            # 2. Walk directory up to max_depth
            for root, dirs, files in os.walk(base_resolved):
                root_path = Path(root).resolve()
                try:
                    rel_parts = root_path.relative_to(base_resolved).parts
                except ValueError:
                    rel_parts = ()

                current_depth = len(rel_parts)

                # Prune ignored directories in-place
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in IGNORED_NAMES and not d.startswith(".")
                ]

                # Stop descending beyond max_depth
                if current_depth >= max_depth:
                    dirs.clear()

                # Index subfolders (preserve shallower mapping over deeper duplicates)
                for d in dirs:
                    d_path = (root_path / d).resolve()
                    d_lower = d.lower()
                    if d_lower not in new_folder_index:
                        new_folder_index[d_lower] = d_path
                    d_space = d_lower.replace("_", " ")
                    if d_space not in new_folder_index:
                        new_folder_index[d_space] = d_path
                    d_under = d_lower.replace(" ", "_")
                    if d_under not in new_folder_index:
                        new_folder_index[d_under] = d_path

                    # Also index relative path from root
                    try:
                        rel_slash = str(d_path.relative_to(base_resolved)).replace("\\", "/").lower()
                        if rel_slash not in new_folder_index:
                            new_folder_index[rel_slash] = d_path
                    except ValueError:
                        pass

                # Index files
                for f in files:
                    if f.startswith(".") or f.lower() in IGNORED_NAMES:
                        continue
                    f_path = (root_path / f).resolve()
                    f_lower = f.lower()
                    if f_lower not in new_file_index:
                        new_file_index[f_lower] = f_path
                    f_space = f_lower.replace("_", " ")
                    if f_space not in new_file_index:
                        new_file_index[f_space] = f_path

                    # Index stem without extension
                    f_stem = f_path.stem.lower()
                    if f_stem not in new_file_index:
                        new_file_index[f_stem] = f_path
                    f_stem_space = f_stem.replace("_", " ")
                    if f_stem_space not in new_file_index:
                        new_file_index[f_stem_space] = f_path

                    # Also index relative path from root
                    try:
                        rel_slash = str(f_path.relative_to(base_resolved)).replace("\\", "/").lower()
                        if rel_slash not in new_file_index:
                            new_file_index[rel_slash] = f_path
                    except ValueError:
                        pass

        self.folder_index = new_folder_index
        self.file_index = new_file_index
        self._last_indexed_dirs = list(dirs_to_walk)
        self._indexed = True
        logger.info(
            "SmartFileResolver indexed %d folders and %d files.",
            len(self.folder_index),
            len(self.file_index),
        )

    def _is_allowed(self, path: Path, allowed_dirs: List[Path]) -> bool:
        """Validate if path is inside allowed directories using Path.is_relative_to()."""
        resolved = path.resolve()
        for allowed in allowed_dirs:
            try:
                if resolved.is_relative_to(allowed.resolve()):
                    return True
            except (ValueError, AttributeError):
                pass
        return False

    def _validate_path(self, path: Path, allowed_dirs: List[Path]) -> None:
        """Ensure path is within allowed directories or raise PermissionError."""
        if not self._is_allowed(path, allowed_dirs):
            raise PermissionError(f"Access denied: '{path}' is outside allowed directories.")

    def resolve(
        self,
        hint: str,
        allowed_dirs: Optional[List[Union[str, Path]]] = None,
    ) -> Path:
        """Resolve a natural language hint or path to an absolute Path inside ALLOWED_DIRS.

        Follows strict 3-step hierarchy:
        1. Exact Relative Path Match (or direct absolute candidate inside ALLOWED_DIRS).
        2. Composite Path Split (Slash Parsing) - parent folder match + exact child.
        3. Base Name Fuzzy Match (rapidfuzz >= 75) when no slashes present.
        """
        if allowed_dirs is not None:
            dirs = [Path(d).resolve() for d in allowed_dirs]
        else:
            dirs = [Path(d).resolve() for d in get_settings().ALLOWED_DIRS]

        if not self._indexed or not self.folder_index or dirs != self._last_indexed_dirs:
            self._build_index_sync(dirs)

        clean_hint = (hint or "").strip().strip('"').strip("'")
        # Normalize backslashes to forward slashes for consistent parsing
        clean_hint = clean_hint.replace("\\", "/")
        # Task 3.2: Safely handle trailing slashes (e.g. "Downloads/" -> "Downloads")
        while len(clean_hint) > 1 and clean_hint.endswith("/"):
            clean_hint = clean_hint[:-1]

        if not clean_hint or clean_hint in (".", "/", "\\", "root", "default", "sandbox"):
            target = dirs[0]
            self._validate_path(target, dirs)
            return target

        # Direct check for absolute paths or directory traversal attempts
        normalized = normalize_drive_alias(clean_hint)
        cand_input = Path(normalized)
        if cand_input.is_absolute() or ".." in Path(clean_hint).parts:
            cand_resolved = cand_input.resolve()
            if not self._is_allowed(cand_resolved, dirs):
                raise PermissionError(f"Access denied: '{clean_hint}' is outside allowed directories.")
            if cand_resolved.exists():
                return cand_resolved
            raise FileNotFoundError(f"Path '{clean_hint}' not found in allowed directories.")

        hint_lower = clean_hint.lower()

        # -------------------------------------------------------------
        # Step 1: Exact Relative Path Match (bypassing fuzzy match)
        # -------------------------------------------------------------
        for base in dirs:
            rel_cand = (base / clean_hint).resolve()
            if rel_cand.exists() and self._is_allowed(rel_cand, dirs):
                return rel_cand

        # Exact match in folder/file index
        if clean_hint in self.folder_index:
            candidate = self.folder_index[clean_hint]
            self._validate_path(candidate, dirs)
            return candidate.resolve()

        if hint_lower in self.folder_index:
            candidate = self.folder_index[hint_lower]
            self._validate_path(candidate, dirs)
            return candidate.resolve()

        if clean_hint in self.file_index:
            candidate = self.file_index[clean_hint]
            self._validate_path(candidate, dirs)
            return candidate.resolve()

        if hint_lower in self.file_index:
            candidate = self.file_index[hint_lower]
            self._validate_path(candidate, dirs)
            return candidate.resolve()

        # -------------------------------------------------------------
        # Step 2: Composite Path Split (Slash Parsing)
        # -------------------------------------------------------------
        if "/" in clean_hint:
            parent_hint, child_name = clean_hint.rsplit("/", 1)
            parent_lower = parent_hint.lower()

            if not child_name:
                # Hint ended in slash that couldn't be trimmed (or root)
                child_name = ""

            folder_path: Optional[Path] = None

            # Check direct absolute or normalized parent path
            norm_parent = Path(normalize_drive_alias(parent_hint)).resolve()
            if norm_parent.is_dir() and self._is_allowed(norm_parent, dirs):
                folder_path = norm_parent

            # Exact match in folder_index
            if not folder_path:
                if parent_hint in self.folder_index:
                    folder_path = self.folder_index[parent_hint]
                elif parent_lower in self.folder_index:
                    folder_path = self.folder_index[parent_lower]

            # Direct relative directory inside allowed roots
            if not folder_path:
                for base in dirs:
                    direct_p = (base / parent_hint).resolve()
                    if direct_p.is_dir() and self._is_allowed(direct_p, dirs):
                        folder_path = direct_p
                        break

            # Fuzzy match parent_hint *only* against folder_index
            if not folder_path and self.folder_index:
                folder_keys = list(self.folder_index.keys())
                match = process.extractOne(parent_lower, folder_keys)
                if match is not None:
                    matched_key, score, _ = match
                    if score >= 75.0:
                        cand = self.folder_index.get(matched_key)
                        if cand is not None and cand.is_dir():
                            folder_path = cand

            if not folder_path:
                raise FileNotFoundError(f"Could not locate folder matching '{parent_hint}' in allowed directories.")

            self._validate_path(folder_path, dirs)
            if not child_name:
                return folder_path.resolve()

            cand_file = (folder_path / child_name).resolve()
            if cand_file.exists() and self._is_allowed(cand_file, dirs):
                return cand_file

            raise FileNotFoundError(f"Found folder '{folder_path.name}' but file '{child_name}' does not exist inside it.")

        # -------------------------------------------------------------
        # Step 3: Base Name Fuzzy Match (no slashes in clean_hint)
        # -------------------------------------------------------------
        folder_keys = list(self.folder_index.keys())
        file_keys = list(self.file_index.keys())
        all_keys = folder_keys + file_keys

        if all_keys:
            match = process.extractOne(hint_lower, all_keys)
            if match is not None:
                matched_key, score, _ = match
                # Prevent short token false-positives where a tiny substring matches a completely different long query
                if len(matched_key) < 5 and len(hint_lower) >= 8:
                    score = fuzz.ratio(hint_lower, matched_key)
                if score >= 75.0:
                    cand = self.folder_index.get(matched_key) or self.file_index.get(matched_key)
                    if cand is not None:
                        self._validate_path(cand, dirs)
                        return cand.resolve()

        raise FileNotFoundError(f"Path or file matching '{hint}' not found in allowed directories.")


# Module-level convenience singleton instance
smart_resolver = SmartFileResolver.get_instance()
