from __future__ import annotations

import json
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

        for attempt in range(1, self.max_attempts + 1):
            response = self.chat(messages)
            parsed = self._parse_review_response(response, max_findings)
            if parsed is not None:
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

        return {"summary": "", "insights": [], "findings": [], "error": self.last_error or "LLM request failed"}

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

    def _parse_review_response(
        self, response: Optional[str], max_findings: Optional[int]
    ) -> Optional[dict[str, Any]]:
        if not response:
            return None

        lower = response.lower()
        payload = response
        if "```json" in lower:
            payload = response.split("```json", 1)[1].split("```", 1)[0]
        elif "```" in lower:
            payload = response.split("```", 1)[1].split("```", 1)[0]

        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return None

        findings: list[dict[str, Any]] = []
        for item in data.get("findings", []) or []:
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
