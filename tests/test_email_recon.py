# -*- coding: utf-8 -*-
import json, os, sys, unittest
from unittest import mock
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path: sys.path.insert(0, ROOT)
from engine import email_recon as er

class TestGitHub(unittest.TestCase):
    def test_success_rate_limit_422_allowlist(self):
        data=json.dumps({'total_count':42,'items':[{'author':{'login':'alice'},'repository':{'full_name':'alice/r'}},{'author':{'login':'bob'},'repository':{'full_name':'org/r'}}]})
        with mock.patch.object(er,'http_get',return_value=(200,data,None)):
            r=er.check_github_email('x@example.com')
        self.assertEqual(r['commit_count'],42); self.assertIn('alice',r['usernames'])
        with mock.patch.object(er,'http_get',return_value=(403,'','HTTP 403')): self.assertFalse(er.check_github_email('x@example.com')['available'])
        with mock.patch.object(er,'http_get',return_value=(422,'','HTTP 422')): self.assertEqual(er.check_github_email('x@example.com')['commit_count'],0)
        self.assertTrue(er._is_allowed_url('https://api.github.com/search/commits'))

class TestEmailRep(unittest.TestCase):
    def test_success_and_errors(self):
        data=json.dumps({'reputation':'high','references':42,'details':{'credentials_leaked':True,'profiles':['linkedin']}})
        with mock.patch.object(er,'http_get',return_value=(200,data,None)): self.assertTrue(er.check_emailrep('x@example.com')['data']['credentials_leaked'])
        with mock.patch.object(er,'http_get',return_value=(429,'','HTTP 429')): self.assertFalse(er.check_emailrep('x@example.com')['available'])
        with mock.patch.object(er,'http_get',return_value=(200,'bad',None)): self.assertIn('invalid JSON',er.check_emailrep('x@example.com')['error'])

class TestDoh(unittest.TestCase):
    def test_security_levels(self):
        mapping={('example.com','MX'):[{'type':15,'data':'10 mail.example.com.'}],('example.com','TXT'):[{'type':16,'data':'"v=spf1 ~all"'}],('_dmarc.example.com','TXT'):[{'type':16,'data':'"v=DMARC1; p=reject"'}],('google._domainkey.example.com','TXT'):[{'type':16,'data':'"v=DKIM1; p=x"'}]}
        with mock.patch.object(er,'_doh_query',side_effect=lambda n,t,timeout=10:mapping.get((n,t),[])):
            r=er.check_email_domain_security('example.com')
        self.assertEqual(r['risk'],'low'); self.assertIn('google',r['dkim_selectors'])
        with mock.patch.object(er,'_doh_query',return_value=[]): self.assertEqual(er.check_email_domain_security('example.com')['risk'],'high')
        with mock.patch.object(er,'http_get',return_value=(200,'bad',None)): self.assertIsNone(er._doh_query('example.com','MX'))

class TestHIBP(unittest.TestCase):
    def test_no_key_and_breaches(self):
        with mock.patch.dict(os.environ,{},clear=True): self.assertFalse(er.check_breaches('x@example.com')['available'])
        data=json.dumps([{'Name':'Adobe','Title':'Adobe','BreachDate':'2013-01-01','PwnCount':1},{'Name':'LinkedIn','Title':'LinkedIn','BreachDate':'2021-01-01','PwnCount':2}])
        with mock.patch.dict(os.environ,{'HIBP_API_KEY':'k'}),mock.patch.object(er,'http_get',return_value=(200,data,None)),mock.patch.object(er,'_HIBP_MIN_INTERVAL',0): self.assertEqual(er.check_breaches('x@example.com')['count'],2)

class TestIntegration(unittest.TestCase):
    def test_gravatar_validation_and_github(self):
        with mock.patch.object(er,'http_get',return_value=(200,'',None)): self.assertTrue(er.check_gravatar('x@example.com')['exists'])
        with self.assertRaises(ValueError): er.recon_email(None,{'email':'bad','check_breach':False,'check_rep':False,'check_domain':False})
        gh={'commit_count':1,'error':None}
        with mock.patch.object(er,'check_gravatar',return_value={}),mock.patch.object(er,'check_github_email',return_value=gh): self.assertEqual(er.recon_email(None,{'email':'x@example.com','check_breach':False,'check_rep':False,'check_domain':False})['github']['commit_count'],1)

if __name__=='__main__': unittest.main(verbosity=2)
