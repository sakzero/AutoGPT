import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from ..config import Config

RUFF_SEVERITY_BY_PREFIX = {
    "e": "low",
    "f": "low",
    "w": "low",
    "d": "low",
    "n": "low",
    "b": "medium",
    "s": "high",
}


def _run_command(cmd: List[str], cwd: str) -> str | None:
    if not shutil.which(cmd[0]):
        return None
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.stdout
    except Exception:
        return None


def run_ruff(
    target_path: str,
    base_path: str,
    include_paths: Optional[Sequence[str]] = None,
) -> List[Dict[str, str]]:
    targets = _normalize_targets(target_path, include_paths)
    cmd = ["ruff", "check", "--exit-zero", "--output-format", "json"]
    if getattr(Config, "RUFF_ISOLATED", False):
        cmd.append("--isolated")
    select = (getattr(Config, "RUFF_SELECT", "") or "").strip()
    if select:
        cmd.extend(["--select", select])
    cmd.extend(targets if targets else [target_path])
    output = _run_command(cmd, cwd=target_path)
    if not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []

    findings: List[Dict[str, str]] = []
    for entry in data:
        rel_file = _relpath(entry.get("filename"), base_path)
        code = entry.get("code")
        findings.append(
            {
                "tool": "ruff",
                "file": rel_file,
                "line": entry.get("location", {}).get("row"),
                "code": code,
                "message": entry.get("message"),
                "severity": _ruff_severity(code),
            }
        )
    return findings


def run_bandit(
    target_path: str,
    base_path: str,
    include_paths: Optional[Sequence[str]] = None,
) -> List[Dict[str, str]]:
    targets = _normalize_targets(target_path, include_paths)
    cmd = ["bandit", "-f", "json", "-q", "--exit-zero"]
    skip = (getattr(Config, "BANDIT_SKIP", "") or "").strip()
    if skip:
        cmd.extend(["-s", skip])
    exclude = (getattr(Config, "BANDIT_EXCLUDE", "") or "").strip()
    if exclude:
        cmd.extend(["-x", exclude])
    if targets:
        cmd.extend(targets)
    else:
        cmd.extend(["-r", target_path])
    output = _run_command(cmd, cwd=target_path)
    if not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []

    findings: List[Dict[str, str]] = []
    for result in data.get("results", []):
        rel_file = _relpath(result.get("filename"), base_path)
        severity = (result.get("issue_severity") or "info").lower()
        findings.append(
            {
                "tool": "bandit",
                "file": rel_file,
                "line": result.get("line_number"),
                "code": result.get("test_id"),
                "severity": severity,
                "message": result.get("issue_text"),
            }
        )
    return findings


def collect_quality_findings(
    target_path: str,
    include_paths: Optional[Sequence[str]] = None,
) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    findings.extend(run_ruff(target_path, target_path, include_paths=include_paths))
    findings.extend(run_bandit(target_path, target_path, include_paths=include_paths))
    return _deduplicate(findings)


def _ruff_severity(code: str | None) -> str:
    if not code:
        return "info"
    level = RUFF_SEVERITY_BY_PREFIX.get(code[0].lower())
    return level or "info"


def _deduplicate(findings: List[Dict[str, str]]) -> List[Dict[str, str]]:
    unique: dict[tuple[str | None, str | None, int | None, str | None, str | None], Dict[str, str]] = {}
    for item in findings:
        key = (
            item.get("tool"),
            item.get("file"),
            item.get("line"),
            item.get("code"),
            item.get("message"),
        )
        if key not in unique:
            unique[key] = item
    return list(unique.values())


def _relpath(path: str | None, base: str) -> str | None:
    if not path:
        return path
    try:
        rel = os.path.relpath(path, base)
        return rel.replace("\\", "/")
    except Exception:
        return path


def _normalize_targets(target_path: str, include_paths: Optional[Sequence[str]]) -> List[str]:
    if not include_paths:
        return []
    root = Path(target_path).resolve()
    targets: List[str] = []
    for entry in include_paths:
        cleaned = (entry or "").strip().replace("\\", "/")
        if not cleaned or not cleaned.endswith(".py"):
            continue
        candidate = root / cleaned
        if not candidate.exists() or not candidate.is_file():
            continue
        targets.append(cleaned)
    return targets
