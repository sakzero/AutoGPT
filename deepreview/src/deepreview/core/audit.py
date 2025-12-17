from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple


@dataclass(frozen=True)
class HeuristicRule:
    name: str
    pattern: re.Pattern[str]
    severity: str
    description: str
    recommendation: str


RULES: Tuple[HeuristicRule, ...] = (
    HeuristicRule(
        name="eval_exec_usage",
        pattern=re.compile(r"\b(eval|exec)\s*\("),
        severity="high",
        description="Detected direct use of eval/exec which can execute untrusted input.",
        recommendation="Avoid eval/exec. Use safe parsers or explicit dispatch tables instead.",
    ),
    HeuristicRule(
        name="pickle_untrusted",
        pattern=re.compile(r"\b(pickle\.loads|pickle\.load)\s*\("),
        severity="high",
        description="Unpickling arbitrary data can lead to remote code execution.",
        recommendation="Only unpickle trusted sources or migrate to safe serialization formats (json, pydantic).",
    ),
    HeuristicRule(
        name="yaml_unsafe_load",
        pattern=re.compile(r"\byaml\.load\s*\("),
        severity="high",
        description="yaml.load without SafeLoader may execute arbitrary objects.",
        recommendation="Use yaml.safe_load or specify SafeLoader/CSafeLoader explicitly.",
    ),
    HeuristicRule(
        name="subprocess_shell_true",
        pattern=re.compile(r"\bsubprocess\.(run|popen|Popen)\s*\([^)]*shell\s*=\s*True"),
        severity="high",
        description="Subprocess executed with shell=True may enable command injection.",
        recommendation="Avoid shell=True, pass arguments as a list and validate user-controlled data.",
    ),
    HeuristicRule(
        name="weak_hash",
        pattern=re.compile(r"\bhashlib\.(md5|sha1)\s*\("),
        severity="medium",
        description="MD5/SHA1 are weak for security-sensitive hashing.",
        recommendation="Use SHA-256 or stronger algorithms (hashlib.sha256/sha512 or blake2).",
    ),
    HeuristicRule(
        name="requests_insecure_verify",
        pattern=re.compile(r"\brequests\.(get|post|put|delete|request)\s*\([^)]*verify\s*=\s*False"),
        severity="medium",
        description="TLS verification disabled for HTTP requests.",
        recommendation="Remove verify=False or provide certificate pinning/truststore overrides.",
    ),
    HeuristicRule(
        name="jwt_disable_verification",
        pattern=re.compile(r"\bjwt\.decode\s*\([^)]*verify\s*=\s*False"),
        severity="high",
        description="JWT verification disabled, allowing token forgery.",
        recommendation="Always verify JWT signatures and audiences.",
    ),
    HeuristicRule(
        name="hardcoded_secret",
        pattern=re.compile(r"(API_KEY|SECRET|TOKEN|PASSWORD)\s*=\s*['\"][^'\"]+['\"]"),
        severity="medium",
        description="Potential hard-coded credential found.",
        recommendation="Move secrets to environment variables or secret managers.",
    ),
    HeuristicRule(
        name="tempfile_mktemp",
        pattern=re.compile(r"\btempfile\.mktemp\s*\("),
        severity="medium",
        description="tempfile.mktemp is insecure due to race conditions.",
        recommendation="Use tempfile.NamedTemporaryFile or mkstemp instead.",
    ),
)


class HeuristicAuditor:
    """Light-weight text heuristics to surface obvious risks without an LLM."""

    def __init__(self, rules: Tuple[HeuristicRule, ...] = RULES, scan_context: bool = False):
        self.rules = rules
        self.scan_context = scan_context

    def run(
        self,
        diff_text: str,
        context_text: Optional[str] = None,
        analysis_source: str = "diff",
    ) -> List[Dict[str, Optional[str]]]:
        findings: List[Dict[str, Optional[str]]] = []
        seen: set[tuple[str, str | None, int | None]] = set()
        findings.extend(self._scan_diff(diff_text, seen))
        normalized_source = (analysis_source or "diff").lower()
        if diff_text and normalized_source != "diff":
            findings.extend(self._scan_plain(diff_text, source=normalized_source, seen=seen))
        if self.scan_context and context_text:
            findings.extend(self._scan_plain(context_text, source="context", seen=seen))
        return findings

    def _scan_diff(self, diff_text: str, seen: set[tuple[str, str | None, int | None]]) -> List[Dict[str, Optional[str]]]:
        findings: List[Dict[str, Optional[str]]] = []
        current_file: Optional[str] = None
        current_line: Optional[int] = None

        for raw_line in diff_text.splitlines():
            if raw_line.startswith("+++ b/"):
                current_file = raw_line[6:].strip() or None
                continue
            if raw_line.startswith("@@"):
                plus_index = raw_line.find("+")
                if plus_index != -1:
                    segment = raw_line[plus_index + 1 :].split(" ", 1)[0]
                    start = segment.split(",", 1)[0]
                    try:
                        current_line = int(start) - 1
                    except ValueError:
                        current_line = None
                continue
            if not raw_line or raw_line[0] not in "+- ":
                continue
            if raw_line[0] == "+" and not raw_line.startswith("+++"):
                current_line = current_line + 1 if current_line is not None else None
                content = raw_line[1:]
                findings.extend(
                    self._match_rules(
                        content,
                        current_file,
                        current_line,
                        seen,
                    )
                )
            elif raw_line[0] == " ":
                current_line = current_line + 1 if current_line is not None else None
        return findings

    def _scan_plain(
        self,
        text: str,
        source: str,
        seen: set[tuple[str, str | None, int | None]],
    ) -> List[Dict[str, Optional[str]]]:
        findings: List[Dict[str, Optional[str]]] = []
        for idx, raw_line in enumerate(text.splitlines(), start=1):
            findings.extend(
                self._match_rules(
                    raw_line,
                    source,
                    idx,
                    seen,
                )
            )
        return findings

    def _match_rules(
        self,
        line: str,
        file_path: Optional[str],
        line_number: Optional[int],
        seen: set[tuple[str, str | None, int | None]],
    ) -> List[Dict[str, Optional[str]]]:
        matches: List[Dict[str, Optional[str]]] = []
        for rule in self.rules:
            if not rule.pattern.search(line):
                continue
            identity = (rule.name, file_path, line_number)
            if identity in seen:
                continue
            seen.add(identity)
            matches.append(
                {
                    "title": rule.name.replace("_", " ").title(),
                    "severity": rule.severity,
                    "description": rule.description,
                    "recommendation": rule.recommendation,
                    "file": file_path,
                    "line": line_number,
                    "evidence": line.strip(),
                }
            )
        return matches
