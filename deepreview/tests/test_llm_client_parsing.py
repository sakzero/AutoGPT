import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT / "deepreview" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from deepreview.core.llm_client import LLMClient


def _client() -> LLMClient:
    return object.__new__(LLMClient)


def test_parse_review_response_extracts_json_from_prose():
    client = _client()
    response = (
        "Sure — here is the JSON payload:\n"
        '{\n  "summary": "ok",\n  "insights": [],\n  "findings": []\n}\n'
        "Thanks."
    )
    parsed = client._parse_review_response(response, max_findings=None)
    assert parsed is not None
    assert parsed["summary"] == "ok"


def test_parse_review_response_extracts_json_from_fence():
    client = _client()
    response = "```json\n{\"summary\":\"ok\",\"insights\":[],\"findings\":[]}\n```"
    parsed = client._parse_review_response(response, max_findings=None)
    assert parsed is not None
    assert parsed["summary"] == "ok"


def test_parse_review_response_accepts_top_level_list():
    client = _client()
    response = (
        "[\n"
        "  {\"title\":\"T\",\"severity\":\"high\",\"confidence\":\"low\",\"file\":\"a.py\",\"line\":1,"
        "\"description\":\"d\",\"recommendation\":\"r\"}\n"
        "]"
    )
    parsed = client._parse_review_response(response, max_findings=None)
    assert parsed is not None
    assert parsed["findings"]
    assert parsed["findings"][0]["title"] == "T"
