# -*- coding: utf-8 -*-
"""Offline unit tests for the secure code reviewer."""
import os
import sys
import unittest

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from engine import code_reviewer


class TestRulesMetadata(unittest.TestCase):
    def test_metadata_shape_and_ids(self):
        rows = code_reviewer.rules_metadata()
        self.assertIsInstance(rows, list)
        self.assertTrue(rows)
        required = {"id", "name", "severity", "cwe", "desc", "fix"}
        ids = []
        for row in rows:
            self.assertTrue(required.issubset(row))
            self.assertNotIn("pattern", row)
            ids.append(row["id"])
        self.assertEqual(len(ids), len(set(ids)))
        for rule_id in ("SQLI", "XSS", "CMDI", "SECRET", "PATH", "EVAL",
                        "DESER", "WEAKCRYPTO", "DEBUG", "TLSVERIFY",
                        "RANDOM", "BINDALL"):
            self.assertIn(rule_id, ids)


class TestRuleDetection(unittest.TestCase):
    def scan(self, code):
        return code_reviewer.scan_code_text(code, filename="test.py")

    def assertRule(self, rule_id, code):
        self.assertTrue(any(f["rule_id"] == rule_id for f in self.scan(code)), code)

    def test_injection_rules(self):
        self.assertRule("SQLI", 'cur.execute("SELECT * FROM t WHERE id = " + uid)')
        self.assertRule("SQLI", 'cur.execute(f"SELECT * FROM t WHERE id = {uid}")')
        self.assertRule("SQLI", 'cur.execute("SELECT * FROM t WHERE id = {}".format(uid))')
        self.assertRule("CMDI", 'os.system("ping " + host)')
        self.assertRule("CMDI", 'subprocess.run(cmd, shell=True)')
        self.assertFalse(any(f["rule_id"] == "SQLI" for f in self.scan('cur.execute("SELECT * FROM t WHERE id = ?", (uid,))')))

    def test_web_and_secret_rules(self):
        self.assertRule("XSS", "el.innerHTML = userInput")
        self.assertRule("XSS", "document.write(userInput)")
        self.assertRule("SECRET", 'DB_PASSWORD = "SuperSecret123!"')
        self.assertRule("SECRET", 'api_key = "abc123xyz"')

    def test_other_rules(self):
        cases = {
            "PATH": 'open("../../etc/passwd").read()',
            "EVAL": "eval(user_input)",
            "DESER": "obj = pickle.loads(data)",
            "WEAKCRYPTO": 'hashlib.md5(b"x")',
            "DEBUG": 'app.run(host="127.0.0.1", debug=True)',
            "TLSVERIFY": "requests.get(url, verify=False)",
            "RANDOM": "random.randint(0, 10)",
            "BINDALL": 'app.run(host="0.0.0.0")',
        }
        for rule_id, code in cases.items():
            with self.subTest(rule_id=rule_id):
                self.assertRule(rule_id, code)

    def test_clean_code(self):
        self.assertEqual(self.scan("def add(a, b):\n    return a + b\n"), [])


class TestMaskingAndEntryPoint(unittest.TestCase):
    def test_secret_masking(self):
        masked = code_reviewer._mask_secret('DB_PASSWORD = "SuperSecret123!"')
        self.assertIn('"Su', masked)
        self.assertIn("*", masked)
        self.assertNotIn("perSecret123", masked)
        findings = code_reviewer.scan_code_text('DB_PASSWORD = "SuperSecret123!"')
        self.assertNotIn("SuperSecret", findings[0]["snippet"])

    def test_scan_entry_inline_and_multiple(self):
        result = code_reviewer.scan_code(None, {"code": 'os.system("x" + y)'})
        self.assertEqual(result["files_scanned"], 1)
        self.assertEqual(result["risk_level"], "critical")
        result = code_reviewer.scan_code(None, {"files": [
            {"name": "a.py", "content": 'os.system("x" + y)'},
            {"name": "b.py", "content": "eval(user_input)"},
        ]})
        self.assertEqual(result["files_scanned"], 2)
        self.assertEqual({f["file"] for f in result["findings"]}, {"a.py", "b.py"})

    def test_empty_and_sorting(self):
        with self.assertRaises(ValueError):
            code_reviewer.scan_code(None, {})
        result = code_reviewer.scan_code(None, {"code": "random.randint(1, 10)\nos.system('x' + y)\neval(z)"})
        order = [code_reviewer.SEVERITY_ORDER[f["severity"]] for f in result["findings"]]
        self.assertEqual(order, sorted(order))
        self.assertGreaterEqual(result["severity_stats"]["critical"], 1)
        self.assertGreaterEqual(result["severity_stats"]["high"], 1)


class TestRiskLevel(unittest.TestCase):
    def test_risk_levels(self):
        self.assertEqual(code_reviewer._risk_level([]), "none")
        self.assertEqual(code_reviewer._risk_level([{"severity": "critical"}]), "critical")
        self.assertEqual(code_reviewer._risk_level([{"severity": "low"}, {"severity": "high"}]), "high")
        self.assertLess(code_reviewer.SEVERITY_ORDER["critical"], code_reviewer.SEVERITY_ORDER["low"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
