from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore


FRAMEWORK_HINTS = {
    "django": ["django"],
    "flask": ["flask"],
    "fastapi": ["fastapi", "starlette"],
    "pydantic": ["pydantic"],
    "sqlalchemy": ["sqlalchemy"],
}


class ProjectAnalyzer:
    """Collects lightweight metadata about a Python repository."""

    def __init__(self, target_dir: str):
        self.root_dir = os.path.abspath(target_dir)
        self.entry_file: Optional[str] = None
        self.framework = "general"
        self.python_version: Optional[str] = None
        self.dependencies: List[str] = []
        self.detected_frameworks: List[str] = []
        self.notes: List[str] = []

    def detect_entry_point(self) -> bool:
        """Gather repository metadata to help downstream analysis."""
        print(f"[Analyzer] Inspecting {self.root_dir} (general code audit mode)...")
        self._load_project_metadata()
        self._detect_frameworks()
        return True

    def _load_project_metadata(self) -> None:
        self._read_pyproject()
        self._read_requirements()
        python_version_file = Path(self.root_dir, ".python-version")
        if python_version_file.exists() and not self.python_version:
            self.python_version = python_version_file.read_text(encoding="utf-8").strip()

    def _read_pyproject(self) -> None:
        pyproject_path = Path(self.root_dir, "pyproject.toml")
        if not pyproject_path.exists():
            return
        try:
            data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            self.notes.append("pyproject.toml could not be parsed.")
            return
        project = data.get("project") or {}
        requires = project.get("requires-python")
        if requires:
            self.python_version = requires
        deps = project.get("dependencies") or []
        self.dependencies.extend(self._normalize_deps(deps))
        poetry = data.get("tool", {}).get("poetry", {})
        poetry_python = poetry.get("dependencies", {}).get("python")
        if poetry_python and not self.python_version:
            self.python_version = poetry_python
        poetry_deps = poetry.get("dependencies", {})
        self.dependencies.extend(
            self._normalize_deps(dep for dep in poetry_deps if dep.lower() != "python")
        )

    def _read_requirements(self) -> None:
        requirements_file = Path(self.root_dir, "requirements.txt")
        if not requirements_file.exists():
            return
        try:
            deps = [
                line.strip()
                for line in requirements_file.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            self.dependencies.extend(self._normalize_deps(deps))
        except OSError:
            self.notes.append("requirements.txt could not be read.")

    def _normalize_deps(self, deps) -> List[str]:
        normalized: List[str] = []
        for dep in deps:
            if not dep:
                continue
            cleaned = dep.split(";")[0].strip()
            if cleaned:
                normalized.append(cleaned)
        return normalized

    def _detect_frameworks(self) -> None:
        dep_lower = [d.lower() for d in self.dependencies]
        detected = set()
        for name, hints in FRAMEWORK_HINTS.items():
            for hint in hints:
                if any(hint in dep for dep in dep_lower):
                    detected.add(name)
        key_files = {
            "django": ["manage.py", "settings.py"],
            "flask": ["app.py"],
            "fastapi": ["main.py"],
        }
        for framework, files in key_files.items():
            for file_name in files:
                if Path(self.root_dir, file_name).exists():
                    detected.add(framework)
        self.detected_frameworks = sorted(detected)
        if self.detected_frameworks:
            self.framework = self.detected_frameworks[0]

    def gather_metadata(self) -> Dict[str, Any]:
        unique_deps = sorted({dep for dep in self.dependencies if dep})
        return {
            "python_version": self.python_version,
            "dependency_count": len(unique_deps),
            "dependencies": unique_deps[:50],
            "frameworks": self.detected_frameworks,
            "notes": self.notes,
        }
