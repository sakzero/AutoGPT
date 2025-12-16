import json
import os
from datetime import datetime, timezone

def write_report(report_path: str, payload: dict):
    """
    Persists the structured report to disk with ISO timestamp metadata.
    """
    os.makedirs(os.path.dirname(os.path.abspath(report_path)) or ".", exist_ok=True)
    enriched = dict(payload)
    enriched.setdefault("generated_at", datetime.now(timezone.utc).isoformat())
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(enriched, handle, indent=2, ensure_ascii=False)
    print(f"[Report] Saved to {report_path}")
