# -*- coding: utf-8 -*-
import hashlib, json, os, sys, unittest
from unittest import mock
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path: sys.path.insert(0, ROOT)
from engine import email_recon as er

class TestEmailValidation(unittest.TestCase):
    def test_valid_emails(self):
        for value in ('user@example.com','a.b+c@sub.example.co.uk','info@github.com','x@protonmail.com'):
            self.assertTrue(er.is_valid_email(value))
    def test_invalid_emails(self):
        for value in ('','user@','@example.com','user@@x.com','user@localhost','user @x.com','a'*300+'@x.com','user@.com','noatsign.com'):
            self.assertFalse(er.is_valid_email(value))
    def test_normalization(self): self.assertEqual(er.normalize_email(' USER@Example.COM '),'user@example.com')
    def test_normalize_invalid(self):
        for value in ('',None,123,'  '): self.assertIsNone(er.normalize_email(value))

class TestParseParts(unittest.TestCase):
    def test_basic(self):
        parts=er.parse_email_parts('user@example.com'); self.assertEqual(parts['provider'],'unknown'); self.assertFalse(parts['is_role_based'])
    def test_providers(self):
        self.assertEqual(er.parse_email_parts('x@gmail.com')['provider'],'Google'); self.assertEqual(er.parse_email_parts('x@outlook.com')['provider'],'Microsoft')
    def test_role_disposable(self):
        self.assertTrue(er.parse_email_parts('admin@example.com')['is_role_based']); self.assertTrue(er.parse_email_parts('x@mailinator.com')['is_disposable'])
    def test_hashes(self):
        parts=er.parse_email_parts('test@example.com'); self.assertEqual(parts['gravatar_md5'],hashlib.md5(b'test@example.com').hexdigest()); self.assertEqual(parts['sha256'],hashlib.sha256(b'test@example.com').hexdigest())
    def test_invalid(self): self.assertIsNone(er.parse_email_parts('bad'))

class TestAllowlist(unittest.TestCase):
    def test_allowed(self):
        for url in ('https://haveibeenpwned.com/x','https://emailrep.io/x','https://www.gravatar.com/avatar/x','https://cloudflare-dns.com/dns-query','https://api.github.com/search/commits'): self.assertTrue(er._is_allowed_url(url))
    def test_blocked(self):
        for url in ('http://localhost/','http://127.0.0.1/','https://evil.com/','ftp://haveibeenpwned.com/','file:///etc/passwd'): self.assertFalse(er._is_allowed_url(url))

class TestGravatar(unittest.TestCase):
    def test_exists(self):
        with mock.patch.object(er,'http_get',return_value=(200,'',None)): self.assertIn('abc123',er.check_gravatar('abc123')['url'])
    def test_missing(self):
        with mock.patch.object(er,'http_get',return_value=(404,'','HTTP 404')): self.assertIsNone(er.check_gravatar('abc123')['url'])

class TestReconEntry(unittest.TestCase):
    def test_invalid(self):
        with self.assertRaises(ValueError): er.recon_email(None,{'email':'bad'})
    def test_disabled(self):
        result=er.recon_email(None,{'email':'user@example.com','check_breach':False,'check_rep':False,'check_gravatar':False,'check_github':False,'check_domain':False}); self.assertEqual(result['parts']['local'],'user')
    def test_no_raw_email(self):
        result=er.recon_email(None,{'email':'secret@example.com','check_breach':False,'check_rep':False,'check_gravatar':False,'check_github':False,'check_domain':False}); self.assertNotIn('secret@example.com',json.dumps(result))

class TestEmailRep(unittest.TestCase):
    def test_success(self):
        body=json.dumps({'reputation':'high','references':42,'details':{'credentials_leaked':True,'profiles':['linkedin']}})
        with mock.patch.object(er,'http_get',return_value=(200,body,None)): self.assertTrue(er.check_emailrep('x@example.com')['data']['credentials_leaked'])
    def test_rate_invalid(self):
        with mock.patch.object(er,'http_get',return_value=(429,'','HTTP 429')): self.assertFalse(er.check_emailrep('x@example.com')['available'])
        with mock.patch.object(er,'http_get',return_value=(200,'bad',None)): self.assertIn('invalid JSON',er.check_emailrep('x@example.com')['error'])

class TestDohDomain(unittest.TestCase):
    def test_full_and_empty(self):
        mapping={('example.com','MX'):[{'type':15,'data':'10 mail.example.com.'}],('example.com','TXT'):[{'type':16,'data':'"v=spf1 ~all"'}],('_dmarc.example.com','TXT'):[{'type':16,'data':'"v=DMARC1; p=reject"'}],('google._domainkey.example.com','TXT'):[{'type':16,'data':'"v=DKIM1; p=x"'}]}
        with mock.patch.object(er,'_doh_query',side_effect=lambda n,t,timeout=10:mapping.get((n,t),[])): self.assertEqual(er.check_email_domain_security('example.com')['risk'],'low')
        with mock.patch.object(er,'_doh_query',return_value=[]): self.assertEqual(er.check_email_domain_security('example.com')['risk'],'high')
    def test_doh_errors(self):
        with mock.patch.object(er,'http_get',return_value=(200,'bad',None)): self.assertIsNone(er._doh_query('example.com','MX'))

class TestGitHub(unittest.TestCase):
    def test_success_rate_422(self):
        body=json.dumps({'total_count':42,'items':[{'author':{'login':'alice'},'repository':{'full_name':'alice/r'}}]})
        with mock.patch.object(er,'http_get',return_value=(200,body,None)): self.assertIn('alice',er.check_github_email('x@example.com')['usernames'])
        with mock.patch.object(er,'http_get',return_value=(403,'','HTTP 403')): self.assertFalse(er.check_github_email('x@example.com')['available'])
        with mock.patch.object(er,'http_get',return_value=(422,'','HTTP 422')): self.assertEqual(er.check_github_email('x@example.com')['commit_count'],0)

class TestHIBP(unittest.TestCase):
    def test_no_key(self):
        with mock.patch.dict(os.environ,{},clear=True): self.assertFalse(er.check_breaches('x@example.com')['available'])
    def test_breaches_errors(self):
        body=json.dumps([{'Name':'LinkedIn','Title':'LinkedIn','BreachDate':'2021-01-01','PwnCount':2}])
        with mock.patch.dict(os.environ,{'HIBP_API_KEY':'k'}),mock.patch.object(er,'http_get',return_value=(200,body,None)),mock.patch.object(er,'_HIBP_MIN_INTERVAL',0): self.assertEqual(er.check_breaches('x@example.com')['count'],1)
        with mock.patch.dict(os.environ,{'HIBP_API_KEY':'k'}),mock.patch.object(er,'http_get',return_value=(401,'','HTTP 401')),mock.patch.object(er,'_HIBP_MIN_INTERVAL',0): self.assertIn('invalid API key',er.check_breaches('x@example.com')['error'])

if __name__=='__main__': unittest.main(verbosity=2)
