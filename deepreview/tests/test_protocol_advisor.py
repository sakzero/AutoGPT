import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT / "deepreview" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from deepreview.core.protocols import ProtocolAdvisor


def test_protocol_advisor_detects_websocket():
    diff = "from flask_socketio import SocketIO\nsocketio = SocketIO(app)\n"
    context = ""
    advisor = ProtocolAdvisor()
    description = advisor.describe(diff, context)
    assert "WebSocket" in description or "socket.io" in description.lower()
