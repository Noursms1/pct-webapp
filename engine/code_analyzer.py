# -*- coding: utf-8 -*-
"""AST taint analyzer with scoped state and configurable heuristics."""

import ast
import json
import re
from pathlib import Path

_DEFAULT_SUSPICIOUS_PARAM_NAMES = {
    "input", "raw_input", "data", "payload", "query", "param", "params",
    "user_input", "userid", "user_id", "userdata", "user_data", "name",
    "username", "user_name", "filename", "file", "filepath", "file_path",
    "path", "url", "uri", "target", "host", "hostname", "endpoint", "cmd",
    "command", "script", "code", "source", "text", "content", "value",
    "token", "key", "api_key", "apikey",
}
_DEFAULT_SUSPICIOUS_SUFFIXES = (
    "_id", "_input", "_data", "_name", "_path", "_file", "_url", "_uri",
    "_host", "_target", "_cmd", "_token", "_key", "_secret", "_pwd", "_password",
)
_DEFAULT_TAINT_SOURCES = {
    "input", "raw_input", "request.args", "request.args.get", "request.form",
    "request.form.get", "request.json", "request.json.get", "request.get_json",
    "request.data", "request.values", "request.cookies", "request.headers",
    "request.files", "sys.argv", "os.environ.get", "os.getenv",
}


def _load_taint_config():
    names = set(_DEFAULT_SUSPICIOUS_PARAM_NAMES)
    suffixes = set(_DEFAULT_SUSPICIOUS_SUFFIXES)
    sources = set(_DEFAULT_TAINT_SOURCES)
    path = Path(__file__).resolve().parent.parent / "taint_patterns.json"
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            names.update(data.get("suspicious_param_names", []) or [])
            suffixes.update(data.get("suspicious_suffixes", []) or [])
            sources.update(data.get("extra_taint_sources", []) or [])
        except (OSError, ValueError, TypeError):
            pass
    return names, tuple(sorted(suffixes)), sources


SUSPICIOUS_PARAM_NAMES, SUSPICIOUS_SUFFIXES, TAINT_SOURCES = _load_taint_config()


def _is_suspicious_param(name):
    if not isinstance(name, str) or not name:
        return False
    low = name.lower()
    return low in SUSPICIOUS_PARAM_NAMES or any(low.endswith(s) for s in SUSPICIOUS_SUFFIXES)


class TaintAnalyzer(ast.NodeVisitor):
    def __init__(self, source_code):
        self.source = source_code
        self.lines = source_code.splitlines()
        self.tainted = set()
        self.tainted_params = {}
        self.findings = []
        self._seen = set()
        self._current_func = "<module>"

    def _dotted(self, node):
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        return None

    def _is_source(self, node):
        if isinstance(node, ast.Call):
            name = self._dotted(node.func) or ""
            return name in ("input", "raw_input") or any(name == src or name.endswith("." + src) for src in TAINT_SOURCES)
        if isinstance(node, ast.Subscript):
            base = self._dotted(node.value) or ""
            return base in TAINT_SOURCES or any(base.startswith(src + ".") for src in TAINT_SOURCES)
        if isinstance(node, ast.Attribute):
            name = self._dotted(node) or ""
            return any(name == src or name.startswith(src + ".") for src in TAINT_SOURCES)
        if isinstance(node, ast.Name):
            return node.id in TAINT_SOURCES
        return False

    def is_tainted(self, node):
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.BinOp):
            return self.is_tainted(node.left) or self.is_tainted(node.right)
        if isinstance(node, ast.JoinedStr):
            return any(self.is_tainted(v) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return self.is_tainted(node.value)
        if isinstance(node, ast.NamedExpr):
            return self.is_tainted(node.value)
        if isinstance(node, ast.Subscript):
            return self._is_source(node) or self.is_tainted(node.value)
        if isinstance(node, ast.Attribute):
            return self._is_source(node) or self.is_tainted(node.value)
        if isinstance(node, ast.Call):
            return self._is_source(node) or any(self.is_tainted(a) for a in node.args) or any(self.is_tainted(k.value) for k in node.keywords if k.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self.is_tainted(e) for e in node.elts)
        if isinstance(node, ast.Dict):
            return any(self.is_tainted(k) for k in node.keys if k) or any(self.is_tainted(v) for v in node.values)
        if isinstance(node, ast.IfExp):
            return self.is_tainted(node.body) or self.is_tainted(node.orelse)
        return False

    def _extract_param_name(self, node):
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.tainted_params:
                return self.tainted_params[child.id]
            if isinstance(child, ast.Call):
                name = self._dotted(child.func) or ""
                if name in ("input", "raw_input"):
                    return "input"
        return None

    def _resolve_param(self, node, snippet):
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.tainted_params:
                return self.tainted_params[child.id]
        match = re.search(r"[+]\s*(\w+)|\b(\w+)\s*[,)]", snippet)
        return (match.group(1) or match.group(2)) if match else "?"

    def add(self, node, rule_id, name, severity, cwe, desc, fix):
        line = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0)
        key = (self._current_func, line, rule_id, col)
        if key in self._seen:
            return
        self._seen.add(key)
        snippet = self.lines[line - 1].strip()[:120] if 0 < line <= len(self.lines) else ""
        self.findings.append({"line": line, "col": col, "rule_id": rule_id, "type": name,
                              "severity": severity, "cwe": cwe, "snippet": snippet,
                              "desc": desc, "fix": fix, "param": self._resolve_param(node, snippet),
                              "function": self._current_func, "analysis": "ast"})

    def visit_FunctionDef(self, node):
        saved_tainted = self.tainted.copy()
        saved_params = self.tainted_params.copy()
        previous = self._current_func
        self._current_func = node.name
        try:
            args = list(getattr(node.args, "posonlyargs", [])) + list(node.args.args) + list(node.args.kwonlyargs)
            for arg in args + ([node.args.vararg] if node.args.vararg else []) + ([node.args.kwarg] if node.args.kwarg else []):
                if _is_suspicious_param(arg.arg):
                    self.tainted.add(arg.arg)
                    self.tainted_params[arg.arg] = arg.arg
            self.generic_visit(node)
        finally:
            self.tainted = saved_tainted
            self.tainted_params = saved_params
            self._current_func = previous

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node):
        if self.is_tainted(node.value):
            source = self._extract_param_name(node.value)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.add(target.id)
                    if source:
                        self.tainted_params[target.id] = source
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None and self.is_tainted(node.value) and isinstance(node.target, ast.Name):
            self.tainted.add(node.target.id)
            self.tainted_params[node.target.id] = self._extract_param_name(node.value) or node.target.id
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        if self.is_tainted(node.value) and isinstance(node.target, ast.Name):
            self.tainted.add(node.target.id)
        self.generic_visit(node)

    def visit_NamedExpr(self, node):
        if self.is_tainted(node.value) and isinstance(node.target, ast.Name):
            self.tainted.add(node.target.id)
            source = self._extract_param_name(node.value)
            if source:
                self.tainted_params[node.target.id] = source
        self.generic_visit(node)

    def _is_safe_yaml_loader(self, node):
        for kw in node.keywords:
            if kw.arg != "Loader":
                continue
            value = kw.value
            if isinstance(value, ast.Name) and value.id in ("SafeLoader", "CSafeLoader"):
                return True
            if isinstance(value, ast.Attribute) and value.attr in ("SafeLoader", "CSafeLoader"):
                return True
        return False

    def visit_Call(self, node):
        fname = self._dotted(node.func) or ""
        last = fname.rsplit(".", 1)[-1]
        tainted = any(self.is_tainted(a) for a in node.args) or any(self.is_tainted(k.value) for k in node.keywords if k.value)
        if last in ("execute", "executemany") and node.args:
            query = node.args[0]
            parameterized = isinstance(query, ast.Constant) and isinstance(query.value, str) and re.search(r"(\?|%s|:\w+)", query.value)
            if self.is_tainted(query) and not parameterized:
                self.add(node, "SQLI_AST", "SQL Injection (AST)", "critical", "CWE-89", "SQL query uses tainted data.", "Use parameterized queries.")
        if fname in ("os.system", "os.popen") and tainted:
            self.add(node, "CMDI_AST", "Command Injection (AST)", "critical", "CWE-78", "OS command uses tainted data.", "Use shell=False with list args.")
        if fname.startswith("subprocess."):
            shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)
            first = node.args[0] if node.args else None
            if shell_true or (first is not None and not isinstance(first, (ast.List, ast.Tuple)) and self.is_tainted(first)):
                self.add(node, "CMDI_AST", "Command Injection (AST)", "critical", "CWE-78", "Subprocess uses unsafe command input.", "Use shell=False with list args.")
        if last == "open" and node.args and self.is_tainted(node.args[0]):
            self.add(node, "PATH_AST", "Path Traversal (AST)", "high", "CWE-22", "File path uses tainted data.", "Validate path against a safe base.")
        if last in ("eval", "exec") and tainted:
            self.add(node, "EVAL_AST", "Code Injection (AST)", "critical", "CWE-95", "eval/exec uses tainted data.", "Use ast.literal_eval or explicit parsing.")
        if fname in ("pickle.loads", "pickle.load", "marshal.loads", "marshal.load") and tainted:
            self.add(node, "DESER_AST", "Insecure Deserialization (AST)", "critical", "CWE-502", "Deserializer uses untrusted data.", "Use JSON or a safe format.")
        if fname == "yaml.load" and not self._is_safe_yaml_loader(node):
            self.add(node, "DESER_AST", "Insecure Deserialization (AST)", "critical", "CWE-502", "yaml.load lacks a safe loader.", "Use yaml.safe_load.")
        if fname.startswith("requests.") and node.args and self.is_tainted(node.args[0]):
            self.add(node, "SSRF_AST", "SSRF (AST)", "critical", "CWE-918", "Request URL uses tainted data.", "Validate URLs and block internal networks.")
        self.generic_visit(node)


def analyze_ast(code_text):
    try:
        tree = ast.parse(code_text)
    except (SyntaxError, TypeError, ValueError):
        return []
    analyzer = TaintAnalyzer(code_text)
    try:
        analyzer.visit(tree)
    except Exception:
        return []
    return analyzer.findings
