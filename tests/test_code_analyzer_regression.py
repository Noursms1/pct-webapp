# -*- coding: utf-8 -*-
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from engine.code_analyzer import analyze_ast, _is_suspicious_param, SUSPICIOUS_PARAM_NAMES, SUSPICIOUS_SUFFIXES, TAINT_SOURCES


class TestConfig(unittest.TestCase):
    def test_defaults_and_json(self):
        self.assertIn("user_id", SUSPICIOUS_PARAM_NAMES)
        self.assertIn("body", SUSPICIOUS_PARAM_NAMES)
        self.assertIn("_id", SUSPICIOUS_SUFFIXES)
        self.assertIn("_payload", SUSPICIOUS_SUFFIXES)
        self.assertIn("request.args.get", TAINT_SOURCES)
        self.assertIn("sys.stdin", TAINT_SOURCES)

    def test_param_heuristic(self):
        for name in ("user_id", "USER_ID", "my_input", "file_path", "cmd"):
            self.assertTrue(_is_suspicious_param(name))
        for name in ("a", "count", ""):
            self.assertFalse(_is_suspicious_param(name))


class TestScopeAndPropagation(unittest.TestCase):
    def test_no_leak(self):
        code = "def first(user_id):\n pass\ndef second():\n os.system(user_id)\n"
        self.assertFalse(any(x["rule_id"] == "CMDI_AST" for x in analyze_ast(code)))

    def test_suspicious_param_and_function(self):
        result = analyze_ast("def dangerous(host):\n os.system('ping ' + host)\n")
        self.assertTrue(result)
        self.assertEqual(result[0]["function"], "dangerous")

    def test_safe_params_not_tainted(self):
        code = "def add(a, b):\n os.system(str(a))\n"
        self.assertFalse(any(x["rule_id"] == "CMDI_AST" for x in analyze_ast(code)))


class TestNamedExprAndColumns(unittest.TestCase):
    def test_walrus(self):
        code = "def f():\n if (u := input()):\n  eval(u)\n"
        self.assertTrue(any(x["rule_id"] == "EVAL_AST" for x in analyze_ast(code)))

    def test_two_same_line_calls(self):
        code = "def f(cmd):\n os.system(cmd); os.system(cmd)\n"
        findings = [x for x in analyze_ast(code) if x["rule_id"] == "CMDI_AST"]
        self.assertEqual(len(findings), 2)
        self.assertNotEqual(findings[0]["col"], findings[1]["col"])


class TestYaml(unittest.TestCase):
    def test_loader_variants(self):
        for code, expected in (("yaml.load(stream)", True), ("yaml.load(stream, Loader=SafeLoader)", False), ("yaml.load(stream, Loader=yaml.SafeLoader)", False), ("yaml.load(stream, Loader=Loader)", True), ("yaml.safe_load(stream)", False)):
            with self.subTest(code=code):
                source = "def f(stream):\n return " + code + "\n"
                result = analyze_ast(source)
                self.assertEqual(any(x["rule_id"] == "DESER_AST" for x in result), expected)


class TestRegressionRules(unittest.TestCase):
    def test_sql_path_and_clean(self):
        sql = "def f(user_id):\n q = 'SELECT * FROM t WHERE id=' + user_id\n cur.execute(q)\n"
        self.assertTrue(any(x["rule_id"] == "SQLI_AST" for x in analyze_ast(sql)))
        path = "def f(name):\n return open('/data/' + name).read()\n"
        self.assertTrue(any(x["rule_id"] == "PATH_AST" for x in analyze_ast(path)))
        self.assertEqual(analyze_ast("def add(a, b):\n return a + b\n"), [])

    def test_malformed_empty(self):
        self.assertEqual(analyze_ast("def broken(:"), [])
        self.assertEqual(analyze_ast(""), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
