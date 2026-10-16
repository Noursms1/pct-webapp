# -*- coding: utf-8 -*-
import os,sys,unittest
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)));sys.path.insert(0,ROOT)
from engine import languages,rule_engine
class TestRust(unittest.TestCase):
 def test_detect_counts(self):
  self.assertEqual(languages.detect('main.rs'),'rust');r=languages.get('rust');self.assertIsNotNone(r);self.assertGreaterEqual(len(r.security_rules),15);self.assertEqual(len(r.frameworks),4)
 def test_frameworks(self):
  self.assertEqual({f.name for f in languages.get('rust').frameworks},{'Actix Web','Axum','Rocket','Tokio'})
 def test_patterns(self):
  rules=languages.get('rust').rules_by_id();cases={'RS-SEC-UNSAFE-01':'unsafe { x }','RS-SEC-UNSAFE-02':'std::mem::transmute(x)','RS-SEC-CMDI-01':'Command::new(user_input)','RS-SEC-CMDI-02':'Command::new("sh")','RS-SEC-SQLI-01':'sqlx::query(&format!("SELECT {}", x))','RS-SEC-TLS-01':'.danger_accept_invalid_certs(true)','RS-SEC-CRYPTO-01':'md5::compute(x)','RS-SEC-SECRET-01':'let password = "SuperSecret123";','RS-SEC-SSRF-01':'reqwest::get(url)','RS-SEC-JWT-01':'Validation::insecure()','RS-SEC-PANIC-01':'foo().unwrap()','RS-ENG-MUT-STATIC-01':'static mut X: u32 = 0;','RS-ENG-AS-01':'x as u8','RS-TOKIO-01':'block_on(x)'}
  for rid,code in cases.items():
   with self.subTest(rule=rid):self.assertTrue(rules[rid].pattern.search(code),rid)
 def test_end_to_end_and_clean(self):
  r=rule_engine.scan_multi(None,{'files':[{'name':'server.rs','content':'Command::new(input);\nlet q = format!("SELECT {}", input);\nmd5::compute(x);'}]});self.assertEqual(r['by_language'],{'rust':r['by_language']['rust']});self.assertGreaterEqual(r['total_findings'],3)
  clean=rule_engine.scan_multi(None,{'files':[{'name':'clean.rs','content':'fn add(a:i32,b:i32)->i32 { a+b }'}]});self.assertFalse(any(x['rule_id'].startswith('RS-SEC') for x in clean['findings']))
 def test_stats(self):self.assertIn('rust',languages.stats()['names'])
if __name__=='__main__':unittest.main(verbosity=2)
