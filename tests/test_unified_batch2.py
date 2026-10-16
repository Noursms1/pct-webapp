# -*- coding: utf-8 -*-
import unittest
from engine.unified.suggestion_engine import SuggestionEngine
class TestSuggestions(unittest.TestCase):
 def test_empty(self):self.assertEqual(SuggestionEngine().suggest([]),[])
 def test_nuclei(self):
  r=SuggestionEngine().suggest([{'type':'osint_to_nuclei','severity':'critical','metadata':{'targets':['x.com'],'tags':['cve']}}]);self.assertEqual(r[0]['action'],'nuclei_scan')
 def test_deps(self):
  r=SuggestionEngine().suggest([{'type':'deps_in_code','severity':'high','metadata':{'package':'flask'}}]);self.assertEqual(r[0]['action'],'upgrade_dependency')
class TestScanner(unittest.TestCase):
 def test_unknown(self):
  from engine.unified.unified_scanner import UnifiedScanner
  r=UnifiedScanner().scan('x',['bad']);self.assertEqual(len(r['errors']),1)
 def test_code(self):
  from engine.unified.unified_scanner import UnifiedScanner
  r=UnifiedScanner().scan('x',['code'],{'code':{'code':'eval(x)'}});self.assertIn('code',r['modules_run'])
if __name__=='__main__':unittest.main(verbosity=2)
