import os,sys,tempfile,unittest
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.unified import IntelligenceDB,RuleStore,CorrelationEngine
class TestUnified(unittest.TestCase):
 def test_db_store(self):
  f=tempfile.NamedTemporaryFile(delete=False);f.close();db=IntelligenceDB(f.name);self.assertIn('001_initial.sql',db.applied_migrations());s=RuleStore(db);s.add({'id':'X','title':'SQL','severity':'high','languages':['python']});self.assertIsNotNone(s.get('X'));db.close();os.unlink(f.name)
 def test_correlation(self):
  r=CorrelationEngine().correlate_deps_code({'vulnerabilities':[{'package':'flask','id':'CVE-X','severity':'high'}]},{'findings':[]},'import flask');self.assertEqual(len(r),1)
if __name__=='__main__':unittest.main(verbosity=2)
