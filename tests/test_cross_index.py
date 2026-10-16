# -*- coding: utf-8 -*-
import json, os, sys, unittest
from pathlib import Path
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:sys.path.insert(0,ROOT)
from engine.languages import cross_index
SAMPLE={"generated_at":"x","languages_count":2,"rules_total":4,"by_cwe":[{"cwe":"CWE-89","rules":[{"language":"python","rule_id":"PY-SQL"},{"language":"javascript","rule_id":"JS-SQL"}]},{"cwe":"CWE-79","rules":[{"language":"javascript","rule_id":"JS-XSS"}]}],"by_owasp":[{"id":"A03:2021","rules":[{"language":"python","rule_id":"PY-SQL"}]}],"by_category":{"security":[{"rule_id":"PY-SQL"}]},"cross_links":{"PY-SQL":{"similar":[{"language":"javascript","rule_id":"JS-SQL"}]}},"online":{}}
def put():
 cross_index._INDEX_FILE.parent.mkdir(parents=True,exist_ok=True);cross_index._INDEX_FILE.write_text(json.dumps(SAMPLE),encoding='utf-8');cross_index._CACHE.update(data=None,mtime=0)
def clean():
 try:cross_index._INDEX_FILE.unlink()
 except OSError:pass
 cross_index._CACHE.update(data=None,mtime=0)
class TestCrossIndex(unittest.TestCase):
 def setUp(self):put()
 def tearDown(self):clean()
 def test_summary(self):
  s=cross_index.summary();self.assertTrue(s['available']);self.assertEqual(s['languages_count'],2);self.assertEqual(s['cwe_count'],2);self.assertEqual(s['cross_links'],1)
 def test_cwe(self):self.assertEqual(len(cross_index.lookup_cwe('cwe-89')),2);self.assertEqual(cross_index.lookup_cwe('CWE-999'),[])
 def test_owasp(self):self.assertEqual(len(cross_index.lookup_owasp('a03:2021')),1)
 def test_similar_category_lists(self):self.assertEqual(len(cross_index.similar_rules('PY-SQL')),1);self.assertEqual(len(cross_index.by_category('security')),1);self.assertEqual(cross_index.by_category('none'),[])
 def test_missing(self):clean();self.assertFalse(cross_index.available());self.assertEqual(cross_index.summary(),{'available':False})
 def test_registry_helpers(self):
  from engine import languages
  self.assertEqual(len(languages.cwe_rules('CWE-89')),2);self.assertEqual(len(languages.owasp_rules('A03:2021')),1);self.assertTrue(languages.cross_summary()['available'])
 def test_bundled_sources(self):
  sys.path.insert(0,os.path.join(ROOT,'scripts'));import fetch_rules
  self.assertEqual(len(fetch_rules.CWE_TOP),25);self.assertEqual(len(fetch_rules.OWASP),10);self.assertIn('A03:2021',fetch_rules.OWASP_CWE)
if __name__=='__main__':unittest.main(verbosity=2)
