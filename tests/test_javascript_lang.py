# -*- coding: utf-8 -*-
import os,sys,unittest
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:sys.path.insert(0,ROOT)
from engine import languages
class TestJavaScript(unittest.TestCase):
 def test_loaded_detected(self):
  self.assertIsNotNone(languages.get('javascript')); self.assertEqual(languages.detect('app.js'),'javascript'); self.assertEqual(languages.detect('x.ts'),'javascript')
 def test_counts_frameworks(self):
  js=languages.get('javascript'); self.assertGreaterEqual(len(js.security_rules),20); self.assertGreaterEqual(len(js.engineering_rules),10); self.assertEqual(len(js.frameworks),5); self.assertGreaterEqual(len(js.branches),5)
 def test_security_patterns(self):
  js=languages.get('javascript'); ids=js.rules_by_id(); cases={'JS-SEC-XSS-01':'el.innerHTML = x','JS-SEC-EVAL-01':'eval(x)','JS-SEC-CMDI-01':"require('child_process').exec(cmd)",'JS-SEC-SQLI-02':'db.query(`SELECT ${id}`)','JS-SEC-SSRF-01':'fetch(req.query.url)','JS-SEC-JWT-02':'jwt.decode(token)','JS-SEC-SECRET-01':'const password = "secret123";'}
  for rid,code in cases.items():
   with self.subTest(rid=rid):self.assertTrue(ids[rid].pattern.search(code))
 def test_framework_branch(self):
  js=languages.get('javascript'); self.assertTrue(js.rules_for_framework('React')); self.assertTrue(js.rules_for_branch('web_backend'))
 def test_registry_stats(self): self.assertIn('javascript',languages.all_metadata())
if __name__=='__main__':unittest.main(verbosity=2)
