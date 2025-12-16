import json
import os
import shutil
import subprocess
from typing import Dict, List

RUFF_SEVERITY_BY_PREFIX = {
    "e": "high",
    "f": "high",
    "w": "medium",
    "d": "medium",
    "n": "medium",
    "b": "high",
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


def run_ruff(target_path: str, base_path: str) -> List[Dict[str, str]]:
    output = _run_command(
        ["ruff", "check", target_path, "--exit-zero", "--output-format", "json"],
        cwd=target_path,
    )
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


def run_bandit(target_path: str, base_path: str) -> List[Dict[str, str]]:
    output = _run_command(
        ["bandit", "-r", target_path, "-f", "json", "-q", "--exit-zero"],
        cwd=target_path,
    )
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


def collect_quality_findings(target_path: str) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    findings.extend(run_ruff(target_path, target_path))
    findings.extend(run_bandit(target_path, target_path))
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
