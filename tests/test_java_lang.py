# -*- coding: utf-8 -*-
import os,sys,unittest
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:sys.path.insert(0,ROOT)
from engine import languages
class TestJava(unittest.TestCase):
 def test_loaded(self):self.assertIsNotNone(languages.get('java'));self.assertEqual(languages.detect('App.java'),'java')
 def test_counts(self):
  j=languages.get('java');self.assertGreaterEqual(len(j.security_rules),25);self.assertGreaterEqual(len(j.engineering_rules),8);self.assertEqual(len(j.frameworks),4)
 def test_patterns(self):
  ids=languages.get('java').rules_by_id()
  for rid,code in {'JAVA-SEC-SQLI-01':'stmt.executeQuery("x" + id);','JAVA-SEC-CMDI-01':'Runtime.getRuntime().exec(x);','JAVA-SEC-DESER-01':'ObjectInputStream x;','JAVA-SEC-XXE-01':'DocumentBuilderFactory.newInstance();','JAVA-SEC-SECRET-01':'String password = "secret123";'}.items():self.assertTrue(ids[rid].pattern.search(code),rid)
 def test_frameworks_branches(self):
  j=languages.get('java');self.assertTrue(j.rules_for_framework('Spring Boot'));self.assertTrue(j.rules_for_branch('web_backend'))
if __name__=='__main__':unittest.main(verbosity=2)
