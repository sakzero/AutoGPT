import ast
import os
from dataclasses import dataclass
from typing import List, Set

PROTOCOL_HEADERS = {
    "websocket": "The target hosts WebSocket/socket.io handlers. Use `websocket-client` or `socketio.Client` to connect and emit crafted events.",
    "grpc": "The code defines gRPC services. Use the `grpc` Python package with generated stubs to call service methods with malicious payloads.",
    "cli": "Entry points accept CLI arguments/subprocess calls. Craft exploits by invoking the CLI with crafted arguments or environment variables.",
    "graphql": "GraphQL endpoints detected. Use crafted GraphQL queries/mutations to access unauthorized data.",
    "raw_tcp": "Raw TCP socket usage detected. Consider writing low-level socket exploits to interact with custom protocols.",
    "static": "Static analysis flagged high-risk patterns (hard-coded secrets, dangerous subprocess usage).",
}

@dataclass
class ProtocolEvidence:
    name: str
    files: Set[str]
    details: List[str]

class ProtocolAdvisor:
    def __init__(self):
        self.detectors = [
            ("websocket", self._detect_websocket),
            ("grpc", self._detect_grpc),
            ("cli", self._detect_cli),
            ("graphql", self._detect_graphql),
            ("raw_tcp", self._detect_raw_tcp),
            ("static", self._detect_static_issues),
        ]

    def gather(self, diff_text: str, context_text: str) -> List[ProtocolEvidence]:
        root = self._extract_root_from_context(context_text) or self._guess_root_from_diff(diff_text)
        evidences = []
        for name, detector in self.detectors:
            evidence = detector(root, diff_text + "\n" + context_text)
            if evidence.files or evidence.details:
                evidences.append(evidence)
        return evidences

    def describe(self, diff_text: str, context_text: str) -> str:
        evidences = self.gather(diff_text, context_text)
        if not evidences:
            return ""

        lines = ["Detected protocol indicators:"]
        for evidence in evidences:
            lines.append(f"- {PROTOCOL_HEADERS[evidence.name]}")
            for detail in evidence.details[:3]:
                lines.append(f"  * {detail}")
        return "\n".join(lines)

    def _extract_root_from_context(self, context_text: str):
        # Context text contains absolute file paths in definitions; use path up to "deepreview"
        for line in context_text.splitlines():
            if "Definition of" in line and "(" in line:
                start = line.find("(")
                end = line.find(")", start)
                if start != -1 and end != -1:
                    file_part = line[start + 1:end]
                    path = file_part.split("from")[-1].strip()
                    if os.path.isabs(path):
                        return os.path.dirname(path)
        return None

    def _guess_root_from_diff(self, diff_text: str):
        # Try to find file headers like "--- File: path"
        for line in diff_text.splitlines():
            if line.strip().startswith("--- File:"):
                candidate = line.split(":", 1)[-1].strip()
                if os.path.isabs(candidate):
                    return os.path.dirname(candidate)
        return None

    def _detect_websocket(self, root_dir, text_blob) -> ProtocolEvidence:
        files, details = self._search_ast(root_dir, self._websocket_indicator)
        if not files and "socketio" in text_blob.lower():
            details.append("SocketIO reference in diff/context.")
        return ProtocolEvidence("websocket", files, details)

    def _detect_grpc(self, root_dir, text_blob) -> ProtocolEvidence:
        files, details = self._search_ast(root_dir, self._grpc_indicator)
        return ProtocolEvidence("grpc", files, details)

    def _detect_cli(self, root_dir, text_blob) -> ProtocolEvidence:
        files, details = self._search_ast(root_dir, self._cli_indicator)
        return ProtocolEvidence("cli", files, details)

    def runtime_hint(self, port: int) -> str:
        if port in {80, 443}:
            return "Runtime check confirmed HTTP(S) service exposed externally."
        if port >= 1024:
            return f"Runtime health check shows port {port} open; consider probing raw TCP protocols."
        return ""

    def _search_ast(self, root_dir, indicator, capture_snippet=False):
        files = set()
        details = []
        if not root_dir:
            return files, details
        for dirpath, _, filenames in os.walk(root_dir):
            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                path = os.path.join(dirpath, filename)
                try:
                    src = open(path, "r", encoding="utf-8").read()
                    tree = ast.parse(src, filename=path)
                    hint = indicator(tree, path, src if capture_snippet else None)
                    if hint:
                        files.add(path)
                        details.extend(hint[:2])
                except (OSError, SyntaxError):
                    continue
        return files, details

    def _websocket_indicator(self, tree, path):
        indicators = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Call) and getattr(getattr(node.value.func, "attr", None), "lower", lambda: "")() == "socketio":
                    indicators.append(f"SocketIO initialization detected in {path}:{getattr(node, 'lineno', '?')}.")
            if isinstance(node, ast.ImportFrom):
                if node.module and "socketio" in node.module.lower():
                    indicators.append(f"Import from {node.module} ({path}:{getattr(node, 'lineno', '?')}).")
        return indicators

    def _grpc_indicator(self, tree, path):
        indicators = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module and "grpc" in node.module.lower():
                    indicators.append(f"Import from {node.module} ({path}:{getattr(node, 'lineno', '?')}).")
            if isinstance(node, ast.Call):
                func_name = getattr(getattr(node.func, "attr", None), "lower", lambda: "")()
                if func_name in {"server", "insecure_channel", "secure_channel"}:
                    indicators.append(f"gRPC call detected: {func_name} ({path}:{getattr(node, 'lineno', '?')}).")
        return indicators

    def _cli_indicator(self, tree, path):
        indicators = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and any(mod in node.module.lower() for mod in ("argparse", "click", "typer")):
                indicators.append(f"CLI module import: {node.module} ({path}:{getattr(node, 'lineno', '?')}).")
            if isinstance(node, ast.Call):
                func_name = getattr(getattr(node.func, "attr", None), "lower", lambda: "")()
                if func_name in {"add_argument", "command", "option"}:
                    indicators.append(f"CLI handler call: {func_name} ({path}:{getattr(node, 'lineno', '?')}).")
        return indicators

    def _detect_graphql(self, root_dir, text_blob):
        files, details = self._search_ast(root_dir, self._graphql_indicator)
        if not files and "graphql" in text_blob.lower():
            details.append("GraphQL reference in diff/context.")
        return ProtocolEvidence("graphql", files, details)

    def _detect_raw_tcp(self, root_dir, text_blob):
        files, details = self._search_ast(root_dir, self._raw_tcp_indicator)
        if not files and "socket.socket" in text_blob.lower():
            details.append("Socket usage reference in diff/context.")
        return ProtocolEvidence("raw_tcp", files, details)

    def _detect_static_issues(self, root_dir, text_blob):
        issues = self._scan_static_patterns(text_blob, root_dir)
        return ProtocolEvidence("static", set(), issues)

    def _graphql_indicator(self, tree, path):
        indicators = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "graphql" in node.module.lower():
                indicators.append(f"GraphQL import: {node.module} ({path}:{getattr(node, 'lineno', '?')}).")
            if isinstance(node, ast.Call):
                func_name = getattr(getattr(node.func, "attr", None), "lower", lambda: "")()
                if func_name in {"grapheneobjecttype", "graphqlview", "execute_async"}:
                    indicators.append(f"GraphQL handler call: {func_name} ({path}:{getattr(node, 'lineno', '?')}).")
        return indicators

    def _raw_tcp_indicator(self, tree, path):
        indicators = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = getattr(getattr(node.func, "attr", None), "lower", lambda: "")()
                if func_name in {"socket", "bind", "listen"}:
                    indicators.append(f"Raw socket handling detected ({path}:{getattr(node, 'lineno', '?')}).")
        return indicators

    def _scan_static_patterns(self, text_blob: str, root_dir: str):
        findings = []
        lowered = text_blob.lower()
        if "subprocess.popen" in lowered or "os.system" in lowered:
            findings.append("Potential dangerous subprocess execution.")
        if "aws_secret_access_key" in lowered or "api_key" in lowered:
            findings.append("Possible hard-coded credential detected.")
        if "eval(" in lowered or "exec(" in lowered:
            findings.append("Dynamic eval/exec usage spotted.")
        return findings
