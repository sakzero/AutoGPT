from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _map_severity(level: str | None) -> str:
    normalized = (level or "").lower()
    if normalized in {"critical", "high"}:
        return "error"
    if normalized == "medium":
        return "warning"
    return "note"


def _build_location(finding: dict[str, Any], target_uri: str) -> dict[str, Any]:
    uri = finding.get("file") or target_uri
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
        }
    }
    line = finding.get("line")
    if isinstance(line, int) and line > 0:
        location["physicalLocation"]["region"] = {"startLine": line}
    return location


def _slugify(text: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", (text or "").strip()).strip("-").lower()
    return cleaned or "rule"


def _build_llm_result(idx: int, finding: dict[str, Any], target_uri: str) -> dict[str, Any]:
    title = finding.get("title") or f"LLM Finding #{idx}"
    description = finding.get("description") or title
    recommendation = finding.get("recommendation")
    message_lines = [description]
    if recommendation:
        message_lines.append(f"Recommendation: {recommendation}")
    message = "\n".join(message_lines)
    return {
        "ruleId": "deepreview-llm",
        "level": _map_severity(finding.get("severity")),
        "message": {"text": message},
        "properties": {
            "title": title,
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
        },
        "locations": [_build_location(finding, target_uri)],
    }


def _build_quality_result(idx: int, finding: dict[str, Any], target_uri: str) -> dict[str, Any]:
    tool = finding.get("tool") or "quality"
    code = finding.get("code") or "check"
    rule_id = f"deepreview-{_slugify(str(tool))}-{_slugify(str(code))}"
    title = f"{tool}:{code}"
    message = finding.get("message") or title
    return {
        "ruleId": rule_id,
        "level": _map_severity(finding.get("severity")),
        "message": {"text": message},
        "properties": {
            "title": title,
            "severity": finding.get("severity"),
            "tool": finding.get("tool"),
            "code": finding.get("code"),
        },
        "locations": [_build_location(finding, target_uri)],
    }


def _build_heuristic_result(idx: int, finding: dict[str, Any], target_uri: str) -> dict[str, Any]:
    title = finding.get("title") or f"Heuristic Finding #{idx}"
    rule_key = finding.get("rule_id") or title
    rule_id = f"deepreview-heuristic-{_slugify(str(rule_key))}"
    description = finding.get("description") or title
    evidence = finding.get("evidence")
    recommendation = finding.get("recommendation")
    message_parts = [description]
    if evidence:
        message_parts.append(f"Evidence: {evidence}")
    if recommendation:
        message_parts.append(f"Recommendation: {recommendation}")
    return {
        "ruleId": rule_id,
        "level": _map_severity(finding.get("severity")),
        "message": {"text": "\n".join(message_parts)},
        "properties": {
            "title": title,
            "severity": finding.get("severity"),
            "source": "heuristic",
        },
        "locations": [_build_location(finding, target_uri)],
    }


def write_sarif(report_data: dict[str, Any], sarif_path: str) -> None:
    analysis = report_data.get("analysis", {})
    artifacts = report_data.get("artifacts", {})
    target_uri = report_data.get("target", {}).get("original", "workspace")
    generated = report_data.get("generated_at", datetime.now(timezone.utc).isoformat())
    llm_findings = analysis.get("llm_findings") or []
    quality_findings = analysis.get("quality_findings") or []
    heuristic_findings = analysis.get("audit_findings") or []
    metadata = analysis.get("metadata") or {}
    protocols = metadata.get("protocol_evidence") or []
    quality_meta = metadata.get("quality_meta") or {}
    reproduction_summary = metadata.get("reproduction_summary") or {
        "attempts": metadata.get("reproduction_count", 0)
    }

    results: list[dict[str, Any]] = []
    for idx, finding in enumerate(llm_findings, start=1):
        results.append(_build_llm_result(idx, finding, target_uri))
    quality_offset = len(results)
    for idx, finding in enumerate(quality_findings, start=1):
        results.append(_build_quality_result(quality_offset + idx, finding, target_uri))
    heuristic_offset = len(results)
    for idx, finding in enumerate(heuristic_findings, start=1):
        results.append(_build_heuristic_result(heuristic_offset + idx, finding, target_uri))

    rules_by_id: dict[str, dict[str, Any]] = {}
    for result in results:
        rule_id = result.get("ruleId")
        if not rule_id:
            continue
        title = (result.get("properties") or {}).get("title") or rule_id
        if rule_id in rules_by_id:
            continue
        rules_by_id[rule_id] = {
            "id": rule_id,
            "name": title,
            "shortDescription": {"text": title},
        }
    rules = list(rules_by_id.values())

    sarif_doc = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DeepReview",
                        "informationUri": "https://github.com/your-org/deepreview",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": report_data.get("status") == "completed",
                        "properties": {
                            "generated_at": generated,
                            "artifacts": artifacts,
                            "scan_mode": analysis.get("scan_mode"),
                            "analysis_source": analysis.get("source"),
                            "run_name": metadata.get("run_name"),
                            "protocol_evidence": protocols,
                            "quality_meta": quality_meta,
                            "reproduction_summary": reproduction_summary,
                        },
                    }
                ],
            }
        ],
    }

    sarif_file = Path(sarif_path)
    sarif_file.parent.mkdir(parents=True, exist_ok=True)
    sarif_file.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
