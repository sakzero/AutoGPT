import os
from dotenv import load_dotenv

# Load from project root
load_dotenv()

class Config:
    # NVIDIA API
    API_KEY = os.getenv("NVIDIA_API_KEY", "").strip()
    BASE_URL = (os.getenv("NVIDIA_BASE_URL") or "https://integrate.api.nvidia.com/v1").strip()
    MODEL_NAME = (os.getenv("MODEL_NAME") or "qwen/qwen3-coder-480b-a35b-instruct").strip()
    
    # Audit Settings
    MAX_TOKENS = 2048
    TEMPERATURE = 0.2
    MAX_CONTEXT_TOKENS = int(os.getenv("MAX_CONTEXT_TOKENS", "256000"))
    CONTEXT_UTILIZATION_FRACTION = float(os.getenv("CONTEXT_UTILIZATION_FRACTION", "0.6"))
    CHARS_PER_TOKEN_ESTIMATE = float(os.getenv("CHARS_PER_TOKEN_ESTIMATE", "4.0"))
    LLM_MAX_RETRIES = int(os.getenv("LLM_MAX_RETRIES", "3"))
    LLM_BACKOFF_SECONDS = float(os.getenv("LLM_BACKOFF_SECONDS", "2.0"))
    LLM_SELF_HEALING_ATTEMPTS = int(os.getenv("LLM_SELF_HEALING_ATTEMPTS", "1"))
    REPORT_LOG_LINE_LIMIT = int(os.getenv("REPORT_LOG_LINE_LIMIT", "100"))
    CANDIDATE_VALIDATION_LIMIT = int(os.getenv("CANDIDATE_VALIDATION_LIMIT", "3"))
    AUTOMATION_MAX_ITERATIONS = int(os.getenv("AUTOMATION_MAX_ITERATIONS", "50"))
    LLM_DIFF_CHUNK_CHARS = int(os.getenv("LLM_DIFF_CHUNK_CHARS", "200000"))
    LLM_DIFF_MAX_SECTIONS = int(os.getenv("LLM_DIFF_MAX_SECTIONS", "20"))
    LLM_MAX_CHUNKS = int(os.getenv("LLM_MAX_CHUNKS", "12"))
    LLM_MAX_SNAPSHOT_CHUNKS = int(os.getenv("LLM_MAX_SNAPSHOT_CHUNKS", "4"))
    HEURISTIC_SCAN_CONTEXT = os.getenv("HEURISTIC_SCAN_CONTEXT", "0") not in {"0", "false", "False", ""}

    # App Settings
    IGNORED_FILES = {"audit.py", "exploit_generated.py", "init_db.py", "setup.py"}
