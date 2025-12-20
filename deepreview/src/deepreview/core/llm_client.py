from __future__ import annotations

import json
import re
import textwrap
import time
from typing import Any, Optional

from openai import OpenAI

from ..config import Config


class LLMClient:
    def __init__(self, max_retries: int | None = None):
        self.last_error: str | None = None
        self.enabled = bool(Config.API_KEY and Config.BASE_URL and Config.MODEL_NAME)
        if self.enabled:
            try:
                self.client = OpenAI(api_key=Config.API_KEY, base_url=Config.BASE_URL)
            except Exception as exc:  # noqa: BLE001
                self.last_error = str(exc)
                self.enabled = False
                self.client = None
                print(f"[LLM] Error: failed to initialize client: {exc}")
        else:
            self.client = None
        retries = Config.LLM_MAX_RETRIES if max_retries is None else max_retries
        self.max_attempts = max(1, retries)
        self.backoff_seconds = max(0.0, Config.LLM_BACKOFF_SECONDS)
        if not self.enabled:
            if not Config.API_KEY:
                print("[LLM] NVIDIA_API_KEY missing; LLM review disabled.")
            elif not Config.BASE_URL:
                print("[LLM] NVIDIA_BASE_URL missing; LLM review disabled.")
            elif not Config.MODEL_NAME:
                print("[LLM] MODEL_NAME missing; LLM review disabled.")

    def chat(self, messages) -> Optional[str]:
        if not self.enabled or not self.client:
            return None
        try:
            completion = self.client.chat.completions.create(
                model=Config.MODEL_NAME,
                messages=messages,
                temperature=Config.TEMPERATURE,
                max_tokens=Config.MAX_TOKENS,
            )
            self.last_error = None
            return completion.choices[0].message.content
        except Exception as exc:  # noqa: BLE001
            self.last_error = str(exc)
            print(f"[LLM] Error: {exc}")
            return None

    def review_changes(
        self,
        diff_content: str,
        context_content: str,
        metadata: Optional[dict[str, Any]] = None,
        protocol_hints: Optional[str] = None,
        max_findings: Optional[int] = None,
    ) -> dict[str, Any]:
        """Run a structured review of the diff and return JSON-friendly output."""

        self.last_error = None
        if not self.enabled:
            return {
                "summary": "LLM review disabled (missing configuration).",
                "insights": ["Provide NVIDIA_API_KEY (and optional MODEL_NAME/NVIDIA_BASE_URL) in CI to enable LLM-based findings."],
                "findings": [],
                "error": self.last_error or "LLM disabled",
            }

        prompt = self._build_review_prompt(
            diff_content,
            context_content,
            metadata or {},
            protocol_hints,
            max_findings,
        )
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a senior Python security auditor. "
                    "Review code diffs conservatively, focus on actionable weaknesses, "
                    "and respond ONLY with valid JSON."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        last_response: str | None = None
        last_response_len = 0
        for attempt in range(1, self.max_attempts + 1):
            response = self.chat(messages)
            last_response = response
            last_response_len = len(response or "")
            parsed = self._parse_review_response(response, max_findings)
            if parsed is not None:
                parsed.setdefault("raw_response_len", last_response_len)
                parsed.setdefault("attempts", attempt)
                return parsed
            if response:
                self.last_error = "LLM response was not valid JSON"

            snippet = (response or "")[:400]
            retry_instruction = textwrap.dedent(
                f"""
                Attempt {attempt} failed because the response was not valid JSON or missed required fields.
                Return ONLY JSON matching the documented schema. Previous response snippet:
                ```
                {snippet}
                ```
                """
            ).strip()
            messages.append({"role": "user", "content": retry_instruction})
            time.sleep(self.backoff_seconds * attempt)

        error_payload: dict[str, Any] = {
            "summary": "",
            "insights": [],
            "findings": [],
            "error": self.last_error or "LLM request failed",
            "raw_response_len": last_response_len,
            "attempts": self.max_attempts,
        }
        if last_response:
            error_payload["raw_response_preview"] = last_response[:400]
        return error_payload

    def _build_review_prompt(
        self,
        diff_content: str,
        context_content: str,
        metadata: dict[str, Any],
        protocol_hints: Optional[str],
        max_findings: Optional[int],
    ) -> str:
        metadata_block = json.dumps(metadata, indent=2, ensure_ascii=False)
        hint_block = f"\nProtocol/analysis hints:\n{protocol_hints}" if protocol_hints else ""
        limit_text = f"up to {max_findings} findings" if max_findings else "the most critical findings"
        return textwrap.dedent(
            f"""
            Perform a static security/code-quality review of the provided repository diff and context.

            Respond ONLY with JSON matching this schema:
            {{
              "summary": "High-level assessment (1-2 sentences)",
              "insights": ["Optional bullet guidance or next steps"],
              "findings": [
                 {{
                   "title": "Short name of the risk",
                   "severity": "critical|high|medium|low|info",
                   "confidence": "high|medium|low",
                   "file": "relative/path.py",
                   "line": 123,
                   "description": "Explain the issue and why it matters",
                   "recommendation": "Concrete remediation guidance"
                 }}
              ]
            }}

            Requirements:
            - Focus on {limit_text} that the organization must review.
            - Prefer referencing exact files/lines found in the diff/context.
            - Do NOT invent behavior you cannot justify from the code.
            - Output MUST start with '{{' and end with '}}' (no prose, no markdown fences).

            Repository metadata:
            {metadata_block}
            {hint_block}

            Diff to review:
            ```
            {diff_content}
            ```

            Additional context (definitions, related code):
            ```
            {context_content}
            ```
            """
        ).strip()

    _FENCE_RE = re.compile(r"```(?P<lang>[a-zA-Z0-9_-]+)?\\s*(?P<body>.*?)\\s*```", re.DOTALL)

    def _parse_review_response(
        self, response: Optional[str], max_findings: Optional[int]
    ) -> Optional[dict[str, Any]]:
        if not response:
            return None

        payload = self._extract_json_payload(response)
        if not payload:
            return None

        try:
            data: Any = json.loads(payload)
        except json.JSONDecodeError:
            return None

        if isinstance(data, list):
            data = {"summary": "", "insights": [], "findings": data}
        if not isinstance(data, dict):
            return None

        findings: list[dict[str, Any]] = []
        findings_field = data.get("findings") or data.get("issues") or data.get("risks") or []
        for item in findings_field or []:
            if not isinstance(item, dict):
                continue
            line_value = item.get("line") or item.get("line_number") or item.get("lineNo")
            try:
                line_number = int(line_value) if line_value is not None else None
            except (TypeError, ValueError):
                line_number = None
            finding = {
                "title": (item.get("title") or "Untitled finding").strip(),
                "severity": self._normalize_severity(item.get("severity")),
                "confidence": self._normalize_confidence(item.get("confidence")),
                "file": (item.get("file") or item.get("path") or "").strip(),
                "line": line_number,
                "description": (item.get("description") or item.get("rationale") or "").strip(),
                "recommendation": (item.get("recommendation") or item.get("remediation") or "").strip(),
            }
            findings.append(finding)

        if max_findings is not None and max_findings > 0:
            findings = findings[: max_findings]

        insights_field = (
            data.get("insights")
            or data.get("guidance")
            or data.get("next_steps")
            or data.get("notes")
            or []
        )
        insights = [str(item).strip() for item in insights_field if str(item).strip()]

        summary = str(data.get("summary", "")).strip()
        return {
            "summary": summary,
            "insights": insights,
            "findings": findings,
        }

    def _normalize_severity(self, value: Any) -> str:
        normalized = str(value or "").strip().lower()
        if normalized in {"critical", "high", "medium", "low", "info"}:
            return normalized
        return "info"

    def _normalize_confidence(self, value: Any) -> str:
        normalized = str(value or "").strip().lower()
        if normalized in {"high", "medium", "low"}:
            return normalized
        return "medium"

    def _extract_json_payload(self, response: str) -> str | None:
        stripped = (response or "").strip()
        if not stripped:
            return None

        fenced = self._extract_fenced_payload(stripped)
        if fenced:
            candidate = fenced.strip()
            if self._looks_like_json(candidate):
                return candidate

        balanced = self._extract_balanced_json(stripped)
        if balanced:
            return balanced.strip()

        if self._looks_like_json(stripped):
            return stripped
        return None

    def _extract_fenced_payload(self, text: str) -> str | None:
        matches = list(self._FENCE_RE.finditer(text))
        if not matches:
            return None

        json_blocks: list[str] = []
        other_blocks: list[str] = []
        for match in matches:
            lang = (match.group("lang") or "").strip().lower()
            body = (match.group("body") or "").strip()
            if not body:
                continue
            if lang == "json":
                json_blocks.append(body)
            else:
                other_blocks.append(body)

        for block in json_blocks:
            if self._looks_like_json(block):
                return block
        for block in other_blocks:
            if self._looks_like_json(block):
                return block
        return json_blocks[0] if json_blocks else other_blocks[0] if other_blocks else None

    def _looks_like_json(self, text: str) -> bool:
        stripped = (text or "").lstrip()
        return stripped.startswith("{") or stripped.startswith("[")

    def _extract_balanced_json(self, text: str) -> str | None:
        first_object = text.find("{")
        first_array = text.find("[")
        if first_object == -1 and first_array == -1:
            return None
        if first_object == -1:
            start = first_array
            open_char, close_char = "[", "]"
        elif first_array == -1:
            start = first_object
            open_char, close_char = "{", "}"
        else:
            start = min(first_object, first_array)
            open_char, close_char = ("{", "}") if start == first_object else ("[", "]")

        depth = 0
        in_string = False
        escape = False
        for idx in range(start, len(text)):
            ch = text[idx]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == "\"":
                    in_string = False
                continue

            if ch == "\"":
                in_string = True
                continue
            if ch == open_char:
                depth += 1
                continue
            if ch == close_char:
                depth -= 1
                if depth == 0:
                    return text[start : idx + 1]

        return None
