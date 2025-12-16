from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

from ..config import Config

IGNORED_DIRECTORIES = {".git", ".venv", "venv", "__pycache__", "deepreview_runs", "deepreview"}


class CodeContextManager:
    """Builds a light-weight semantic index and returns snippets to enrich LLM prompts."""

    def __init__(self, root_dir: str) -> None:
        self.root_dir = os.path.abspath(root_dir)
        self.symbol_index: Dict[str, List[dict[str, str]]] = {}
        self.language = Language(tspython.language())
        self.parser = Parser(self.language)
        approx_chars = (
            Config.MAX_CONTEXT_TOKENS * Config.CONTEXT_UTILIZATION_FRACTION * Config.CHARS_PER_TOKEN_ESTIMATE
        )
        self.context_budget_chars = int(approx_chars) if approx_chars > 0 else None

    def build_index(self) -> None:
        """Walk the project and capture every function/class definition for later lookups."""
        print(f"[Context] Building semantic index for {self.root_dir}...")
        count = 0
        for current_root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES]
            for file_name in files:
                if not file_name.endswith(".py"):
                    continue
                path = os.path.join(current_root, file_name)
                self._index_file(path)
                count += 1
        print(f"[Context] Indexed symbols from {count} Python files.")

    def _index_file(self, file_path: str) -> None:
        try:
            source = Path(file_path).read_bytes()
        except OSError:
            return

        tree = self.parser.parse(source)
        self._visit_definition_nodes(tree.root_node, source, file_path)

    def _visit_definition_nodes(self, node, source: bytes, file_path: str) -> None:
        if node.type in {"function_definition", "class_definition"}:
            name_node = node.child_by_field_name("name")
            if name_node:
                name = self._node_text(name_node, source)
                body = self._node_text(node, source)
                self.symbol_index.setdefault(name, []).append({"file": file_path, "body": body})

        for child in node.children:
            self._visit_definition_nodes(child, source, file_path)

    def retrieve_context(self, diff_text: str, include_paths: Optional[Sequence[str]] = None) -> str:
        """Return supplemental snippets for the files touched by the diff (or include_paths)."""
        context_snippets: List[str] = []
        budget_used = 0
        seen_keys: Set[Tuple[str, str]] = set()

        modified_files = self._extract_files_from_diff(diff_text)
        include_normalized = self._normalize_paths(include_paths or [])
        if include_normalized and not modified_files:
            modified_files = include_normalized.copy()
        elif include_normalized:
            modified_files &= include_normalized

        for rel_path in sorted(modified_files):
            abs_path = os.path.join(self.root_dir, rel_path)
            if not os.path.exists(abs_path):
                continue
            imports, calls = self._analyze_file_dependencies(abs_path)
            for func_name in sorted(calls):
                definition = self._resolve_definition(func_name, imports)
                if not definition:
                    continue
                key = (func_name, definition["file"])
                if key in seen_keys:
                    continue
                snippet = (
                    f"--- Definition of `{func_name}` (from {os.path.basename(definition['file'])}) ---\n"
                    f"{definition['body']}\n"
                )
                snippet_len = len(snippet)
                if self.context_budget_chars and (budget_used + snippet_len) > self.context_budget_chars:
                    break
                context_snippets.append(snippet)
                seen_keys.add(key)
                budget_used += snippet_len

        return "\n".join(context_snippets)

    def _extract_files_from_diff(self, diff_text: str) -> Set[str]:
        files = set(re.findall(r"\+\+\+\s+b/(.*)", diff_text))
        files.update(re.findall(r"--- File:\s*(.*)", diff_text))
        files.update(re.findall(r"--- Untracked File:\s*(.*)", diff_text))
        normalized = set()
        for candidate in files:
            cleaned = candidate.strip()
            if not cleaned:
                continue
            normalized.add(cleaned.replace("\\", "/"))
        return normalized

    def _analyze_file_dependencies(self, file_path: str) -> Tuple[Dict[str, dict], Set[str]]:
        imports: Dict[str, dict] = {}
        calls: Set[str] = set()
        try:
            source_bytes = Path(file_path).read_bytes()
        except OSError:
            return imports, calls

        tree = self.parser.parse(source_bytes)
        self._scan_ast(tree.root_node, source_bytes, imports, calls)
        return imports, calls

    def _scan_ast(self, node, source: bytes, imports: Dict[str, dict], calls: Set[str]) -> None:
        node_type = node.type
        if node_type == "import_statement":
            self._handle_import_statement(node, source, imports)
        elif node_type == "import_from_statement":
            self._handle_import_from_statement(node, source, imports)
        elif node_type == "call":
            func_node = node.child_by_field_name("function")
            if func_node:
                name = self._node_text(func_node, source)
                if name:
                    calls.add(name.split(".")[-1])

        for child in node.children:
            self._scan_ast(child, source, imports, calls)

    def _handle_import_statement(self, node, source: bytes, imports: Dict[str, dict]) -> None:
        for child in node.children:
            if child.type == "dotted_name":
                name = self._node_text(child, source)
                if name:
                    alias = name.split(".")[-1]
                    imports[alias] = {"module": name, "name": name}
            elif child.type == "aliased_import":
                original = child.child_by_field_name("name")
                alias_node = child.child_by_field_name("alias")
                if original and alias_node:
                    name = self._node_text(original, source)
                    alias = self._node_text(alias_node, source)
                    if name and alias:
                        imports[alias] = {"module": name, "name": name}

    def _handle_import_from_statement(self, node, source: bytes, imports: Dict[str, dict]) -> None:
        module_node = node.child_by_field_name("module_name")
        module_name = self._node_text(module_node, source) if module_node else ""
        for child in node.children:
            if child.type == "dotted_name":
                name = self._node_text(child, source)
                if name:
                    alias = name.split(".")[-1]
                    imports[alias] = {"module": module_name, "name": name}
            elif child.type == "aliased_import":
                original = child.child_by_field_name("name")
                alias_node = child.child_by_field_name("alias")
                if original and alias_node:
                    name = self._node_text(original, source)
                    alias = self._node_text(alias_node, source)
                    if name and alias:
                        imports[alias] = {"module": module_name, "name": name}

    def _resolve_definition(self, func_name: str, imports: Dict[str, dict]) -> Optional[dict[str, str]]:
        if func_name in self.symbol_index:
            return self.symbol_index[func_name][0]
        import_entry = imports.get(func_name)
        if not import_entry:
            return None
        target_name = import_entry.get("name") or func_name
        target_key = target_name.split(".")[-1]
        entries = self.symbol_index.get(target_key)
        if entries:
            return entries[0]
        return None

    def _node_text(self, node, source: bytes) -> str:
        if not node:
            return ""
        return source[node.start_byte: node.end_byte].decode("utf-8", errors="ignore")

    def _normalize_paths(self, paths: Sequence[str]) -> Set[str]:
        normalized: Set[str] = set()
        for path in paths:
            if not path:
                continue
            cleaned = path.strip().replace("\\", "/")
            if cleaned.startswith("./"):
                cleaned = cleaned[2:]
            normalized.add(cleaned)
        return normalized
