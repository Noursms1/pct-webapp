# -*- coding: utf-8 -*-
"""AST taint analysis for hidden data-flow vulnerabilities."""

import ast


class TaintAnalyzer(ast.NodeVisitor):
    def __init__(self, source_code):
        self.source = source_code
        self.lines = source_code.splitlines()
        self.tainted = set()
        self.tainted_params = {}
        self.findings = []
        self._seen = set()
        self._current_func = "?"

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
            return name in {"input", "raw_input", "os.getenv", "request.get_json"} or name.startswith("request.") or name.endswith(".get") and name.startswith("request.")
        if isinstance(node, ast.Subscript):
            name = self._dotted(node.value) or ""
            return name.startswith("request.") or name == "sys.argv"
        return False

    def is_tainted(self, node):
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, (ast.BinOp, ast.BoolOp, ast.JoinedStr)):
            values = ([node.left, node.right] if isinstance(node, ast.BinOp) else
                      list(node.values) if isinstance(node, ast.JoinedStr) else node.values)
            return any(self.is_tainted(v) for v in values)
        if isinstance(node, ast.FormattedValue):
            return self.is_tainted(node.value)
        if isinstance(node, ast.Call):
            return self._is_source(node) or any(self.is_tainted(a) for a in node.args) or any(self.is_tainted(k.value) for k in node.keywords)
        if isinstance(node, (ast.Subscript, ast.Attribute)):
            return self._is_source(node) or self.is_tainted(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self.is_tainted(x) for x in node.elts)
        if isinstance(node, ast.Dict):
            return any(self.is_tainted(x) for x in node.keys if x) or any(self.is_tainted(x) for x in node.values)
        if isinstance(node, ast.IfExp):
            return self.is_tainted(node.body) or self.is_tainted(node.orelse)
        return False

    def _param(self, node):
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.tainted_params:
                return self.tainted_params[child.id]
        return "?"

    def add(self, node, rule_id, name, severity, cwe, desc, fix):
        key = (getattr(node, "lineno", 0), rule_id)
        if key in self._seen:
            return
        self._seen.add(key)
        line = getattr(node, "lineno", 0)
        snippet = self.lines[line - 1].strip()[:120] if 0 < line <= len(self.lines) else ""
        self.findings.append({"line": line, "rule_id": rule_id, "type": name,
                              "severity": severity, "cwe": cwe, "snippet": snippet,
                              "desc": desc, "fix": fix, "param": self._param(node),
                              "function": self._current_func, "analysis": "ast"})

    def visit_FunctionDef(self, node):
        previous = self._current_func
        self._current_func = node.name
        args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
        for arg in args:
            self.tainted.add(arg.arg)
            self.tainted_params[arg.arg] = arg.arg
        if node.args.vararg:
            self.tainted.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted.add(node.args.kwarg.arg)
        self.generic_visit(node)
        self._current_func = previous

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node):
        if self.is_tainted(node.value):
            source = self._param(node.value)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.add(target.id)
                    self.tainted_params[target.id] = source
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None and self.is_tainted(node.value) and isinstance(node.target, ast.Name):
            self.tainted.add(node.target.id)
            self.tainted_params[node.target.id] = self._param(node.value)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = self._dotted(node.func) or ""
        last = name.rsplit(".", 1)[-1]
        args_tainted = any(self.is_tainted(a) for a in node.args) or any(self.is_tainted(k.value) for k in node.keywords)
        if last in ("execute", "executemany") and node.args and self.is_tainted(node.args[0]):
            q = node.args[0]
            if not (isinstance(q, ast.Constant) and isinstance(q.value, str) and ("?" in q.value or "%s" in q.value)):
                self.add(node, "SQLI_AST", "SQL Injection (AST)", "critical", "CWE-89", "SQL query uses tainted data.", "Use parameterized queries.")
        if name in ("os.system", "os.popen") and args_tainted:
            self.add(node, "CMDI_AST", "Command Injection (AST)", "critical", "CWE-78", "OS command uses tainted data.", "Use shell=False with a list of arguments.")
        if name.startswith("subprocess."):
            shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)
            first = node.args[0] if node.args else None
            if shell_true or (first is not None and not isinstance(first, (ast.List, ast.Tuple)) and self.is_tainted(first)):
                self.add(node, "CMDI_AST", "Command Injection (AST)", "critical", "CWE-78", "Subprocess uses unsafe command input.", "Use shell=False with a list of arguments.")
        if last == "open" and node.args and self.is_tainted(node.args[0]):
            self.add(node, "PATH_AST", "Path Traversal (AST)", "high", "CWE-22", "File path uses tainted data.", "Validate against a safe base directory.")
        if last in ("eval", "exec") and args_tainted:
            self.add(node, "EVAL_AST", "Code Injection (AST)", "critical", "CWE-95", "eval/exec uses tainted data.", "Use ast.literal_eval or explicit parsing.")
        if name in ("pickle.loads", "pickle.load", "marshal.loads", "marshal.load") and args_tainted:
            self.add(node, "DESER_AST", "Insecure Deserialization (AST)", "critical", "CWE-502", "Deserializer uses untrusted data.", "Use JSON or a safe format.")
        if name == "yaml.load" and not any(k.arg == "Loader" for k in node.keywords):
            self.add(node, "DESER_AST", "Insecure Deserialization (AST)", "critical", "CWE-502", "yaml.load lacks a safe loader.", "Use yaml.safe_load.")
        if name.startswith("requests.") and node.args and self.is_tainted(node.args[0]):
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
