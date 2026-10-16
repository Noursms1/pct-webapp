# -*- coding: utf-8 -*-
import os,sys,unittest
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:sys.path.insert(0,ROOT)
from engine import language_rules as lr
class TestPacks(unittest.TestCase):
 def test_langs(self):
  for lang in ('python','javascript','php','java','go','ruby','csharp','cpp','sql','shell'):self.assertIn(lang,lr.LANGUAGE_PACKS)
 def test_counts(self):
  for pack in lr.LANGUAGE_PACKS.values():self.assertGreaterEqual(len(pack['rules']),7)
 def test_detect(self):
  self.assertEqual(lr.detect_language('a.py'),'python');self.assertEqual(lr.detect_language('b.js'),'javascript');self.assertIsNone(lr.detect_language('x.txt'))
class TestScan(unittest.TestCase):
 def test_python(self):self.assertTrue(lr.scan_with_language("cur.execute('x' + uid)",'python'))
 def test_js(self):self.assertTrue(lr.scan_with_language('eval(x)','javascript'))
 def test_php(self):self.assertTrue(lr.scan_with_language('$x=unserialize($y)','php'))
 def test_clean(self):self.assertEqual(lr.scan_with_language('def add(a,b): return a+b','python'),[])
if __name__=='__main__':unittest.main(verbosity=2)
