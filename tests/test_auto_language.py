import os,sys,unittest,json
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)));sys.path.insert(0,ROOT)
from engine.languages import spec,json_loader,registry
class TestAuto(unittest.TestCase):
 def test_spec(self):
  d=spec.validate_spec({'name':'dummy','extensions':['.dum'],'security_rules':[{'id':'D-1','name':'x','severity':'high','pattern':'danger'}]})
  self.assertEqual(d['name'],'dummy'); self.assertEqual(len(json_loader.load_from_dict(d).security_rules),1)
 def test_invalid(self):
  with self.assertRaises(spec.SpecError):spec.validate_spec({'name':'bad name','extensions':['.x']})
 def test_current_registry(self):
  registry.reload(); self.assertIn('go',registry.list_names()); self.assertEqual(registry.detect('x.go'),'go')
if __name__=='__main__':unittest.main(verbosity=2)
