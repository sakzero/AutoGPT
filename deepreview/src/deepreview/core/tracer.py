from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Optional
from uuid import uuid4


if TYPE_CHECKING:
    from .state import AutomationState


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunTracer:
    """Persist run metadata/artifacts – inspired by Strix telemetry."""

    def __init__(self, run_name: Optional[str] = None, base_dir: Optional[Path] = None):
        self.run_name = run_name or f"run-{uuid4().hex[:8]}"
        root = base_dir or (Path.cwd() / "deepreview_runs")
        self.run_dir = root / self.run_name
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._state_file = self.run_dir / "state.json"
        self.data: Dict[str, Any] = {
            "run_name": self.run_name,
            "created_at": _utcnow(),
            "updated_at": _utcnow(),
            "status": "running",
            "target": {},
            "events": [],
            "llm_messages": [],
            "attempts": [],
            "artifacts": {},
            "notes": [],
        }
        self._write()

    def persist_state(self, state: "AutomationState | Dict[str, Any]") -> None:
        if hasattr(state, "snapshot"):
            payload = state.snapshot()  # type: ignore[assignment]
        else:
            payload = dict(state)
        try:
            self._state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except OSError:
            pass

    def _write(self) -> None:
        self.data["updated_at"] = _utcnow()
        (self.run_dir / "run.json").write_text(
            json.dumps(self.data, indent=2), encoding="utf-8"
        )

    def set_target(self, path: str, analysis_source: str, workspace: Optional[str] = None) -> None:
        self.data["target"] = {
            "path": path,
            "analysis_source": analysis_source,
        }
        if workspace:
            self.data["target"]["workspace"] = workspace
        self._write()

    def log_event(self, phase: str, status: str, info: Optional[Dict[str, Any]] = None) -> None:
        entry = {
            "phase": phase,
            "status": status,
            "info": info or {},
            "timestamp": _utcnow(),
        }
        self.data["events"].append(entry)
        self._write()

    def log_llm_message(self, purpose: str, prompt_bytes: int, response_bytes: int) -> None:
        self.data["llm_messages"].append(
            {
                "purpose": purpose,
                "prompt_bytes": prompt_bytes,
                "response_bytes": response_bytes,
                "timestamp": _utcnow(),
            }
        )
        self._write()

    def log_attempt(
        self,
        iteration: int,
        stdout: str,
        stderr: str,
        success: bool,
    ) -> None:
        record = {
            "iteration": iteration,
            "stdout": stdout,
            "stderr": stderr,
            "success": success,
            "timestamp": _utcnow(),
        }
        self.data["attempts"].append(record)
        self._write()

    def add_note(self, text: str) -> None:
        self.data["notes"].append({"text": text, "timestamp": _utcnow()})
        self._write()

    def record_artifact(self, name: str, path: Path) -> None:
        if path.exists():
            dest = self.run_dir / path.name
            if path.resolve() != dest.resolve():
                try:
                    shutil.copy2(path, dest)
                except OSError:
                    dest.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
            self.data["artifacts"][name] = str(dest)
            self._write()

    def finalize(self, status: str, report_path: Optional[Path] = None) -> None:
        self.data["status"] = status
        if report_path:
            self.record_artifact("report", report_path)
        self._write()

    def run_directory(self) -> Path:
        return self.run_dir
