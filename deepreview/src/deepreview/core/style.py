from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

try:
    from radon.complexity import cc_visit
    from radon.metrics import mi_visit
except ImportError:  # pragma: no cover
    cc_visit = None
    mi_visit = None

IGNORED_DIRS = {".git", ".venv", "venv", "__pycache__", "deepreview_runs", ".tox"}
EXTENSIONS = (".py",)


@dataclass(frozen=True)
class StyleIssue:
    title: str
    severity: str
    description: str
    recommendation: str
    file: Optional[str]
    line: Optional[int]
    metric: str
    value: float


def analyze_style(target_path: str, include_paths: Optional[Sequence[str]] = None) -> List[Dict[str, object]]:
    if not cc_visit or not mi_visit:
        return []
    root = Path(target_path).resolve()
    include_set = None
    if include_paths:
        include_set = {Path(p).as_posix() for p in include_paths}

    findings: List[Dict[str, object]] = []
    for file_path in _iter_python_files(root):
        rel_path = file_path.relative_to(root).as_posix()
        if include_set and rel_path not in include_set:
            continue
        try:
            code = file_path.read_text(encoding="utf-8")
        except OSError:
            continue

        findings.extend(_analyze_complexity(code, rel_path))
        findings.extend(_analyze_maintainability(code, rel_path))
    return [issue.__dict__ for issue in findings]


def _iter_python_files(root: Path):
    for current_root, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for file_name in files:
            if file_name.endswith(EXTENSIONS):
                yield Path(current_root, file_name)


def _analyze_complexity(code: str, rel_path: str) -> List[StyleIssue]:
    issues: List[StyleIssue] = []
    try:
        results = cc_visit(code)
    except Exception:
        return issues
    for block in results:
        severity = _complexity_severity(block.complexity)
        if not severity:
            continue
        title = f"High cyclomatic complexity in {block.name}"
        description = (
            f"{block.name} has cyclomatic complexity {block.complexity}, "
            "which may hinder readability and security review."
        )
        recommendation = "Refactor the function into smaller units or simplify branching logic."
        issues.append(
            StyleIssue(
                title=title,
                severity=severity,
                description=description,
                recommendation=recommendation,
                file=rel_path,
                line=getattr(block, "lineno", None),
                metric="complexity",
                value=float(block.complexity),
            )
        )
    return issues


def _analyze_maintainability(code: str, rel_path: str) -> List[StyleIssue]:
    issues: List[StyleIssue] = []
    try:
        maintainability = mi_visit(code, False)
    except Exception:
        return issues
    severity = _maintainability_severity(maintainability)
    if not severity:
        return issues
    title = "Low maintainability index"
    description = (
        f"File {rel_path} has maintainability index {maintainability:.1f}. "
        "Lower scores indicate harder-to-review code."
    )
    recommendation = "Simplify functions, reduce nesting, or add docstrings/tests to improve clarity."
    issues.append(
        StyleIssue(
            title=title,
            severity=severity,
            description=description,
            recommendation=recommendation,
            file=rel_path,
            line=None,
            metric="maintainability",
            value=float(maintainability),
        )
    )
    return issues


def _complexity_severity(score: float) -> Optional[str]:
    if score >= 20:
        return "high"
    if score >= 10:
        return "medium"
    return None


def _maintainability_severity(score: float) -> Optional[str]:
    if score < 50:
        return "high"
    if score < 70:
        return "medium"
    return None
