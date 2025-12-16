import json
import sys
from pathlib import Path
import textwrap

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT / "deepreview" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from deepreview import cli as cli_module


def _write_real_app(target_dir: Path):
    code = textwrap.dedent(
        """
        import subprocess

        def helper(cmd):
            subprocess.run(cmd, shell=True)

        def run_command():
            user_cmd = input("cmd:")
            helper(user_cmd)
        """
    ).strip()
    target_dir.mkdir(parents=True, exist_ok=True)
    target_dir.joinpath("real_app.py").write_text(code, encoding="utf-8")


def test_cli_fail_on_confirmed(monkeypatch, tmp_path):
    target_dir = tmp_path / "real_app"
    _write_real_app(target_dir)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    monkeypatch.setattr(
        sys,
        "argv",
        ["deepreview-cli", str(target_dir), "--fail-on-confirmed"],
        raising=False,
    )

    class StubLLM:
        def __init__(self, *_, **__):
            pass

        def review_changes(self, diff_content, context_content, metadata=None, protocol_hints=None, max_findings=None):
            return {
                "summary": "Command input flow",
                "insights": ["Validate CLI input"],
                "findings": [
                    {
                        "title": "Stub",
                        "severity": "low",
                        "confidence": "medium",
                        "file": "real_app.py",
                        "line": 1,
                        "description": "LLM placeholder",
                        "recommendation": "n/a",
                    }
                ],
            }

    monkeypatch.setattr(cli_module, "LLMClient", lambda *_, **__: StubLLM())

    with pytest.raises(SystemExit) as excinfo:
        cli_module.main()
    assert excinfo.value.code == 2

    report = json.loads((workspace / "deepreview_report.json").read_text(encoding="utf-8"))
    taint_findings = report["analysis"].get("taint_findings") or []
    assert any(f["severity"] == "high" for f in taint_findings)
    assert "style_findings" in report["analysis"]
    reproduction = report.get("reproduction") or []
    assert reproduction
    first_attempt = reproduction[0]
    assert Path(first_attempt["script"]).exists()
