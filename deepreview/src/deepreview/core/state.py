from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AutomationState:
    """Lightweight run-state tracker inspired by Strix's AgentState."""

    run_name: str
    max_iterations: int = 50
    phase: str = "init"
    iteration: int = 0
    completed: bool = False
    errors: List[str] = field(default_factory=list)
    actions: List[Dict[str, Any]] = field(default_factory=list)
    start_time: str = field(default_factory=_utcnow)
    last_updated: str = field(default_factory=_utcnow)

    def increment_iteration(self) -> None:
        self.iteration += 1
        self.last_updated = _utcnow()

    def set_phase(self, phase: str) -> None:
        self.phase = phase
        self.last_updated = _utcnow()

    def add_action(self, action: Dict[str, Any]) -> None:
        decorated = {
            **action,
            "iteration": self.iteration,
            "timestamp": _utcnow(),
        }
        self.actions.append(decorated)
        self.last_updated = decorated["timestamp"]

    def add_error(self, message: str) -> None:
        self.errors.append(f"[iter={self.iteration}] {message}")
        self.last_updated = _utcnow()

    def set_completed(self) -> None:
        self.completed = True
        self.last_updated = _utcnow()

    def snapshot(self) -> Dict[str, Any]:
        data = asdict(self)
        data["actions"] = list(self.actions)
        data["errors"] = list(self.errors)
        return data


class PhaseContext:
    """Context manager helper to auto log phase transitions."""

    def __init__(self, state: AutomationState, phase: str):
        self.state = state
        self.phase = phase
        self.previous_phase: Optional[str] = None

    def __enter__(self) -> None:
        self.previous_phase = self.state.phase
        self.state.set_phase(self.phase)
        self.state.increment_iteration()

    def __exit__(self, exc_type, exc, _tb) -> None:
        if exc:
            self.state.add_error(f"{self.phase} failed: {exc}")
        if not self.state.completed and self.previous_phase:
            self.state.set_phase(self.previous_phase)
