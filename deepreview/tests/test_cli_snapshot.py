import json
import sys
from pathlib import Path
import textwrap

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT / "deepreview" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from deepreview import cli as cli_module


def _write_sample_module(target_dir: Path):
    code = textwrap.dedent(
        """
        def greet(name: str):
            if not name:
                raise ValueError("name required")
            return f"hello {name}!"
        """
    ).strip()
    target_dir.joinpath("demo.py").write_text(code, encoding="utf-8")


def test_cli_snapshot_generates_report(monkeypatch, tmp_path):
    target_dir = tmp_path / "app"
    target_dir.mkdir()
    _write_sample_module(target_dir)

    work_dir = tmp_path / "workspace"
    work_dir.mkdir()
    metadata_path = work_dir / "run_meta.json"
    monkeypatch.chdir(work_dir)
    monkeypatch.setattr(
        sys,
        "argv",
        ["deepreview-cli", str(target_dir), "--metadata-path", str(metadata_path)],
        raising=False,
    )

    captured = {}

    class DummyLLM:
        def __init__(self, *_, **__):
            pass

        def review_changes(self, diff_content, context_content, metadata=None, protocol_hints=None, max_findings=None):
            captured["diff_len"] = len(diff_content)
            return {
                "summary": "Functions lack error handling",
                "insights": ["Add tests covering error branches"],
                "findings": [
                    {
                        "title": "Missing validation",
                        "severity": "high",
                        "confidence": "medium",
                        "file": "demo.py",
                        "line": 1,
                        "description": "Function raises ValueError without logging",
                        "recommendation": "Handle bad input explicitly",
                    }
                ],
            }

    monkeypatch.setattr(cli_module, "LLMClient", lambda *_, **__: DummyLLM())

    with pytest.raises(SystemExit) as excinfo:
        cli_module.main()
    assert excinfo.value.code == 0

    report_path = work_dir / "deepreview_report.json"
    assert report_path.exists(), "Report should be generated in workspace."
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "completed"
    assert report["analysis"]["source"] == "snapshot"
    assert report["analysis"]["summary"].startswith("Functions")
    assert report["analysis"]["llm_findings"]
    assert report["analysis"]["llm_findings"][0]["title"] == "Missing validation"
    assert "audit_findings" in report["analysis"]
    assert "style_findings" in report["analysis"]
    assert "taint_findings" in report["analysis"]
    assert "project" in report["analysis"]
    assert "project_metadata" in report["analysis"]["metadata"]
    assert "severity_summary" in report["analysis"]
    artifacts = report.get("artifacts", {})
    sarif_path = Path(artifacts["sarif"])
    assert sarif_path.exists()
    assert metadata_path.exists()
    meta = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert meta["status"] == report["status"]
    assert meta["run_directory"] == artifacts["run_directory"]
    assert meta["details"]["heuristic_findings"] == len(report["analysis"]["audit_findings"])
    assert meta["details"]["style_findings"] == len(report["analysis"]["style_findings"])
    assert meta["details"]["taint_findings"] == len(report["analysis"]["taint_findings"])
    assert "severity_summary" in meta["details"]


def test_cli_config_targets(monkeypatch, tmp_path):
    target_dir = tmp_path / "app"
    target_dir.mkdir()
    _write_sample_module(target_dir)

    work_dir = tmp_path / "workspace"
    work_dir.mkdir()

    config_path = tmp_path / "deepreview.yml"
    metadata_path = work_dir / "cfg-meta.json"
    archive_path = work_dir / "cfg-run.zip"
    config_path.write_text(
        textwrap.dedent(
            f"""
            defaults:
              metadata_path: "{metadata_path.as_posix()}"
              fail_on_confirmed: false
              scan_mode: quick
            targets:
              - path: "{target_dir.as_posix()}"
                run_name: "cfg-run"
                archive_run: "{archive_path.as_posix()}"
            """
        ).strip(),
        encoding="utf-8",
    )

    monkeypatch.chdir(work_dir)
    monkeypatch.setattr(sys, "argv", ["deepreview-cli", "--config", str(config_path)], raising=False)

    class DummyLLM:
        def __init__(self, *_, **__):
            pass

        def review_changes(self, diff_content, context_content, metadata=None, protocol_hints=None, max_findings=None):
            return {
                "summary": "Sample",
                "insights": [],
                "findings": [
                    {
                        "title": "Stub",
                        "severity": "medium",
                        "confidence": "high",
                        "file": "demo.py",
                        "line": 1,
                        "description": "desc",
                        "recommendation": "fix",
                    }
                ],
            }

    monkeypatch.setattr(cli_module, "LLMClient", lambda *_, **__: DummyLLM())

    with pytest.raises(SystemExit) as excinfo:
        cli_module.main()
    assert excinfo.value.code == 0

    report = json.loads((work_dir / "deepreview_report.json").read_text(encoding="utf-8"))
    artifacts = report.get("artifacts", {})
    assert Path(artifacts["sarif"]).exists()
    assert report["analysis"].get("scan_mode") == "quick"
    assert "audit_findings" in report["analysis"]
    assert "style_findings" in report["analysis"]
    assert "taint_findings" in report["analysis"]
    assert metadata_path.exists()
    assert archive_path.exists()


def test_cli_writes_summary_markdown(monkeypatch, tmp_path):
    target_dir = tmp_path / "app"
    target_dir.mkdir()
    _write_sample_module(target_dir)

    work_dir = tmp_path / "workspace"
    work_dir.mkdir()
    summary_path = work_dir / "summary.md"
    monkeypatch.chdir(work_dir)

    class DummyLLM:
        def __init__(self, *_, **__):
            pass

        def review_changes(self, diff_content, context_content, metadata=None, protocol_hints=None, max_findings=None):
            return {
                "summary": "Summary section",
                "insights": [],
                "findings": [
                    {
                        "title": "Style issue",
                        "severity": "low",
                        "confidence": "medium",
                        "file": "demo.py",
                        "line": 1,
                        "description": "desc",
                        "recommendation": "n/a",
                    }
                ],
            }

    monkeypatch.setattr(cli_module, "LLMClient", lambda *_, **__: DummyLLM())

    parser = cli_module._build_parser()
    args = parser.parse_args([str(target_dir), "--summary-path", str(summary_path)])

    exit_code = cli_module.run_scan(args)
    assert exit_code in (0, 2)
    assert summary_path.exists()
    assert "Severity distribution" in summary_path.read_text(encoding="utf-8")


def test_cli_writes_github_summary(monkeypatch, tmp_path):
    target_dir = tmp_path / "app"
    target_dir.mkdir()
    _write_sample_module(target_dir)

    work_dir = tmp_path / "workspace"
    work_dir.mkdir()
    step_summary = work_dir / "gh-summary.md"
    monkeypatch.chdir(work_dir)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step_summary))

    class DummyLLM:
        def __init__(self, *_, **__):
            pass

        def review_changes(self, diff_content, context_content, metadata=None, protocol_hints=None, max_findings=None):
            return {
                "summary": "Summary section",
                "insights": [],
                "findings": [
                    {
                        "title": "Style issue",
                        "severity": "low",
                        "confidence": "medium",
                        "file": "demo.py",
                        "line": 1,
                        "description": "desc",
                        "recommendation": "n/a",
                    }
                ],
            }

    monkeypatch.setattr(cli_module, "LLMClient", lambda *_, **__: DummyLLM())

    parser = cli_module._build_parser()
    args = parser.parse_args([str(target_dir)])

    exit_code = cli_module.run_scan(args)
    assert exit_code in (0, 2)
    assert step_summary.exists()
    assert "Severity distribution" in step_summary.read_text(encoding="utf-8")

def test_cli_init_config_generates_template(monkeypatch, tmp_path):
    repo = tmp_path / 'repo'
    repo.mkdir()
    pkg = repo / 'pkg'
    pkg.mkdir()
    pkg.joinpath('sample.py').write_text("print('hi')", encoding='utf-8')

    init_dir = tmp_path / 'workspace'
    init_dir.mkdir()
    config_path = init_dir / 'deepreview.yml'

    monkeypatch.chdir(init_dir)
    monkeypatch.setattr(
        sys,
        'argv',
        ['deepreview-cli', str(repo), '--init-config', str(config_path)],
        raising=False,
    )

    with pytest.raises(SystemExit) as excinfo:
        cli_module.main()
    assert excinfo.value.code == 0

    data = yaml.safe_load(config_path.read_text(encoding='utf-8'))
    assert 'defaults' in data
    assert 'targets' in data
    assert data['targets'][0]['path'] == '.'
    assert any(entry['path'] == 'pkg' for entry in data['targets'])

