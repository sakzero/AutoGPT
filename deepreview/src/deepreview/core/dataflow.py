from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set

IGNORED_DIRS = {".git", ".venv", "venv", "__pycache__", "deepreview_runs", ".tox"}
EXTENSIONS = (".py",)

SOURCE_FUNCTIONS = {
    "input",
    "builtins.input",
    "raw_input",
    "sys.stdin.readline",
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "request.get_json",
    "flask.request.args.get",
    "flask.request.form.get",
    "os.environ.get",
    "os.getenv",
    "sys.argv",
}

SINK_FUNCTIONS = {
    "os.system": "Command execution via os.system",
    "subprocess.call": "Command execution via subprocess",
    "subprocess.run": "Command execution via subprocess",
    "subprocess.Popen": "Command execution via subprocess",
    "eval": "Dynamic evaluation",
    "exec": "Dynamic execution",
    "builtins.eval": "Dynamic evaluation",
    "builtins.exec": "Dynamic execution",
}

SQL_SINK_NAMES = {"execute", "executemany", "raw"}


@dataclass(frozen=True)
class TaintFinding:
    title: str
    severity: str
    description: str
    recommendation: str
    file: Optional[str]
    line: Optional[int]
    function: Optional[str] = None
    sink: Optional[str] = None


@dataclass(frozen=True)
class FunctionSummary:
    name: str
    param_names: List[str]
    return_from_source: bool
    return_from_params: Set[int]
    sink_params: Set[int]


def analyze_taint(target_path: str, include_paths: Optional[Sequence[str]] = None) -> List[Dict[str, object]]:
    root = Path(target_path).resolve()
    include_set = None
    if include_paths:
        include_set = {Path(p).as_posix() for p in include_paths}

    findings: List[Dict[str, object]] = []
    for file_path in _iter_python_files(root):
        rel_path = file_path.relative_to(root).as_posix()
        if include_set and rel_path not in include_set:
            continue
        try:
            code = file_path.read_text(encoding="utf-8")
            tree = ast.parse(code, filename=rel_path)
        except (OSError, SyntaxError):
            continue

        summaries = _build_function_summaries(tree)
        visitor = _TaintVisitor(rel_path, summaries)
        visitor.visit(tree)
        findings.extend(finding.__dict__ for finding in visitor.findings)
    return findings


def _iter_python_files(root: Path):
    for current_root, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for file_name in files:
            if file_name.endswith(EXTENSIONS):
                yield Path(current_root, file_name)


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        prefix = _qualified_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


class _TaintVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, summaries: Dict[str, FunctionSummary]) -> None:
        self.file_path = file_path
        self.function_summaries = summaries
        self.tainted: Set[str] = set()
        self.findings: List[TaintFinding] = []
        self.function_stack: List[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        value_tainted = self._expr_is_tainted(node.value) or self._is_source_call(node.value)
        if value_tainted:
            for target in node.targets:
                for name in self._extract_names(target):
                    self.tainted.add(name)
        self.generic_visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            value_tainted = self._expr_is_tainted(node.value) or self._is_source_call(node.value)
            if value_tainted:
                for name in self._extract_names(node.target):
                    self.tainted.add(name)
            self.generic_visit(node.value)

    def visit_For(self, node: ast.For) -> None:
        if self._expr_is_tainted(node.iter) or self._is_source_call(node.iter):
            for name in self._extract_names(node.target):
                self.tainted.add(name)
        self.generic_visit(node.iter)
        for stmt in node.body:
            self.visit(stmt)

    def visit_Call(self, node: ast.Call) -> None:
        sink_reason = self._is_sink_call(node.func)
        if sink_reason:
            if any(self._expr_is_tainted(arg) for arg in node.args):
                self._record_sink_finding(sink_reason, node)
            for keyword in node.keywords or []:
                if self._expr_is_tainted(keyword.value):
                    self._record_sink_finding(sink_reason, node)
        elif self._is_source_call(node):
            pass
        else:
            self._handle_user_function_sink(node)
        self.generic_visit(node)

    def _record_sink_finding(self, reason: str, node: ast.Call) -> None:
        finding = TaintFinding(
            title=f"Tainted data flows into {reason}",
            severity="high",
            description=f"Potentially untrusted input reaches {reason}.",
            recommendation="Validate, sanitize, or escape user input before invoking this operation.",
            file=self.file_path,
            line=getattr(node, "lineno", None),
            function=self._current_function(),
            sink=reason,
        )
        self.findings.append(finding)

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.Call) and self._is_source_call(node):
            return True
        if isinstance(node, ast.Call):
            summary = self._lookup_summary(node.func)
            if summary:
                if summary.return_from_source:
                    return True
                for idx in summary.return_from_params:
                    arg = _get_argument_by_index(node, idx, summary.param_names)
                    if arg is not None and self._expr_is_tainted(arg):
                        return True
        if isinstance(node, ast.Attribute):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted(node.value) or self._expr_is_tainted(node.slice)  # type: ignore[arg-type]
        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted(node.left) or self._expr_is_tainted(node.right)
        if isinstance(node, ast.BoolOp):
            return any(self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.JoinedStr):
            return any(self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.List) or isinstance(node, ast.Tuple) or isinstance(node, ast.Set):
            return any(self._expr_is_tainted(elt) for elt in node.elts)
        if isinstance(node, ast.Dict):
            return any(self._expr_is_tainted(key) or self._expr_is_tainted(value) for key, value in zip(node.keys, node.values))
        return False

    def _is_source_call(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        name = _qualified_name(node.func)
        return name in SOURCE_FUNCTIONS

    def _is_sink_call(self, node: ast.AST) -> Optional[str]:
        name = _qualified_name(node)
        if name in SINK_FUNCTIONS:
            return SINK_FUNCTIONS[name]
        if isinstance(node, ast.Attribute) and node.attr in SQL_SINK_NAMES:
            return f"{node.attr} (possible SQL execution)"
        return None

    def _handle_user_function_sink(self, node: ast.Call) -> None:
        summary = self._lookup_summary(node.func)
        if not summary or not summary.sink_params:
            return
        for idx in summary.sink_params:
            arg = _get_argument_by_index(node, idx, summary.param_names)
            if arg is not None and self._expr_is_tainted(arg):
                finding = TaintFinding(
                    title=f"Tainted argument flows through {summary.name}",
                    severity="high",
                    description=f"Helper '{summary.name}' routes tainted data into a sensitive sink.",
                    recommendation="Sanitize within the helper or validate inputs before calling it.",
                    file=self.file_path,
                    line=getattr(node, "lineno", None),
                    function=summary.name,
                    sink="helper_sink",
                )
                self.findings.append(finding)

    def _lookup_summary(self, node: ast.AST) -> Optional[FunctionSummary]:
        name = _qualified_name(node)
        return self.function_summaries.get(name)

    def _current_function(self) -> Optional[str]:
        if not self.function_stack:
            return None
        return ".".join(self.function_stack)

    def _extract_names(self, target: ast.AST) -> Set[str]:
        return _extract_target_names(target)


def _build_function_summaries(tree: ast.AST) -> Dict[str, FunctionSummary]:
    summaries: Dict[str, FunctionSummary] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            analyzer = _FunctionAnalyzer(node)
            analyzer.visit(node)
            summaries[node.name] = analyzer.summary(node.name)
    return summaries


class _FunctionAnalyzer(ast.NodeVisitor):
    SOURCE_TOKEN = "source"

    def __init__(self, func_def: ast.FunctionDef) -> None:
        self.param_names = [arg.arg for arg in func_def.args.args]
        self.tainted: Dict[str, Set[str]] = {}
        for idx, name in enumerate(self.param_names):
            self.tainted[name] = {self._param_token(idx)}
        self.return_from_source = False
        self.return_from_params: Set[int] = set()
        self.sink_params: Set[int] = set()

    def _param_token(self, idx: int) -> str:
        return f"param_{idx}"

    def summary(self, name: str) -> FunctionSummary:
        return FunctionSummary(
            name=name,
            param_names=list(self.param_names),
            return_from_source=self.return_from_source,
            return_from_params=set(self.return_from_params),
            sink_params=set(self.sink_params),
        )

    def visit_Return(self, node: ast.Return) -> None:
        if not node.value:
            return
        origins = self._expr_origins(node.value)
        for token in origins:
            if token == self.SOURCE_TOKEN:
                self.return_from_source = True
            elif token.startswith("param_"):
                idx = int(token.split("_", 1)[1])
                self.return_from_params.add(idx)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        origins = self._expr_origins(node.value)
        for target in node.targets:
            for name in _extract_target_names(target):
                self.tainted[name] = set(origins)
        self.generic_visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            origins = self._expr_origins(node.value)
            for name in _extract_target_names(node.target):
                self.tainted[name] = set(origins)
            self.generic_visit(node.value)

    def visit_For(self, node: ast.For) -> None:
        origins = self._expr_origins(node.iter)
        for name in _extract_target_names(node.target):
            self.tainted[name] = set(origins)
        self.generic_visit(node.iter)
        for stmt in node.body:
            self.visit(stmt)

    def visit_Call(self, node: ast.Call) -> None:
        reason = SINK_FUNCTIONS.get(_qualified_name(node.func))
        if not reason and isinstance(node.func, ast.Attribute) and node.func.attr in SQL_SINK_NAMES:
            reason = f"{node.func.attr} (possible SQL execution)"
        if reason:
            for idx, arg in enumerate(node.args):
                for token in self._expr_origins(arg):
                    if token.startswith("param_"):
                        self.sink_params.add(int(token.split("_", 1)[1]))
            for keyword in node.keywords or []:
                for token in self._expr_origins(keyword.value):
                    if token.startswith("param_") and keyword.arg in self.param_names:
                        self.sink_params.add(self.param_names.index(keyword.arg))
        self.generic_visit(node)

    def _expr_origins(self, node: ast.AST) -> Set[str]:
        if isinstance(node, ast.Name):
            return set(self.tainted.get(node.id, set()))
        if isinstance(node, ast.Call):
            name = _qualified_name(node.func)
            if name in SOURCE_FUNCTIONS:
                return {self.SOURCE_TOKEN}
        if isinstance(node, ast.Attribute):
            return self._expr_origins(node.value)
        if isinstance(node, ast.Subscript):
            return self._expr_origins(node.value) | self._expr_origins(node.slice)  # type: ignore[arg-type]
        if isinstance(node, ast.BinOp):
            return self._expr_origins(node.left) | self._expr_origins(node.right)
        if isinstance(node, ast.BoolOp):
            origins: Set[str] = set()
            for value in node.values:
                origins |= self._expr_origins(value)
            return origins
        if isinstance(node, ast.JoinedStr):
            origins: Set[str] = set()
            for value in node.values:
                origins |= self._expr_origins(value)
            return origins
        if isinstance(node, ast.List) or isinstance(node, ast.Tuple) or isinstance(node, ast.Set):
            origins: Set[str] = set()
            for elt in node.elts:
                origins |= self._expr_origins(elt)
            return origins
        if isinstance(node, ast.Dict):
            origins: Set[str] = set()
            for key in node.keys:
                if key:
                    origins |= self._expr_origins(key)
            for value in node.values:
                if value:
                    origins |= self._expr_origins(value)
            return origins
        return set()


def _extract_target_names(target: ast.AST) -> Set[str]:
    names: Set[str] = set()
    if isinstance(target, ast.Name):
        names.add(target.id)
    elif isinstance(target, ast.Tuple) or isinstance(target, ast.List):
        for elt in target.elts:
            names.update(_extract_target_names(elt))
    elif isinstance(target, ast.Attribute):
        names.add(_qualified_name(target))
    return names


def _get_argument_by_index(call: ast.Call, index: int, param_names: List[str]) -> Optional[ast.AST]:
    if index < len(call.args):
        return call.args[index]
    if index < len(param_names):
        param_name = param_names[index]
        for keyword in call.keywords or []:
            if keyword.arg == param_name:
                return keyword.value
    return None
