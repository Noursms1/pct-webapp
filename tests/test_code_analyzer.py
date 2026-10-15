# -*- coding: utf-8 -*-
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from engine.code_analyzer import analyze_ast
from engine import code_reviewer


class TestAstAnalyzer(unittest.TestCase):
    def assert_rule(self, rule, code):
        self.assertTrue(any(item["rule_id"] == rule for item in analyze_ast(code)), code)

    def test_sql_flow(self):
        self.assert_rule("SQLI_AST", "def f(user_id):\n q = 'SELECT * FROM t WHERE id=' + user_id\n cur.execute(q)\n")

    def test_parameterized_sql(self):
        code = "def f(user_id):\n cur.execute('SELECT * FROM t WHERE id=?', (user_id,))\n"
        self.assertFalse(any(x["rule_id"] == "SQLI_AST" for x in analyze_ast(code)))

    def test_command_flow(self):
        self.assert_rule("CMDI_AST", "def f(host):\n cmd = 'ping ' + host\n os.system(cmd)\n")
        self.assert_rule("CMDI_AST", "def f(cmd):\n subprocess.run(cmd, shell=True)\n")

    def test_path_flow(self):
        self.assert_rule("PATH_AST", "def f(name):\n return open('/data/' + name).read()\n")
        self.assertFalse(any(x["rule_id"] == "PATH_AST" for x in analyze_ast("open('/etc/hostname')")))

    def test_eval_deserialization_and_ssrf(self):
        self.assert_rule("EVAL_AST", "def f(payload):\n code = payload\n eval(code)\n")
        self.assert_rule("DESER_AST", "def f(data):\n return pickle.loads(data)\n")
        self.assert_rule("DESER_AST", "def f(data):\n return yaml.load(data)\n")
        self.assertFalse(any(x["rule_id"] == "DESER_AST" for x in analyze_ast("yaml.safe_load(data)")))
        self.assert_rule("SSRF_AST", "def f(url):\n return requests.get(url)\n")

    def test_malformed_and_empty(self):
        self.assertEqual(analyze_ast("def broken(:"), [])
        self.assertEqual(analyze_ast(""), [])


class TestReviewerIntegration(unittest.TestCase):
    def test_hidden_flow_is_merged(self):
        code = "def f(user_id):\n q = 'SELECT * FROM t WHERE id=' + user_id\n cur.execute(q)\n"
        findings = code_reviewer.scan_code_text(code, filename="t.py")
        self.assertTrue(any("SQL" in f["rule_id"] for f in findings))
        self.assertTrue(all(f["file"] == "t.py" for f in findings))

    def test_sorting_and_no_duplicate(self):
        code = 'def f(user_id):\n cur.execute("SELECT * FROM t WHERE id=" + user_id)\n'
        findings = code_reviewer.scan_code_text(code)
        order = [code_reviewer.SEVERITY_ORDER[f["severity"]] for f in findings]
        self.assertEqual(order, sorted(order))
        sql = [f for f in findings if "SQL" in f["rule_id"]]
        self.assertLessEqual(len(sql), 1)

    def test_clean(self):
        self.assertEqual(code_reviewer.scan_code_text("def add(a, b):\n return a + b\n"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
