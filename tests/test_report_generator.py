# -*- coding: utf-8 -*-
import json, os, sys, tempfile, unittest
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path: sys.path.insert(0, ROOT)
from engine import report_generator as rg
from engine.core import HistoryManager

def history(entries):
    fd,path=tempfile.mkstemp(suffix='.json'); os.close(fd); hm=HistoryManager(path)
    for item in entries: hm.add(item['type'],item.get('target',''),'',item.get('details',{}))
    return path

class TestHelpers(unittest.TestCase):
    def test_severity(self): self.assertEqual(rg._norm_sev('CRIT'),'critical'); self.assertEqual(rg._norm_sev('x'),'unknown')
    def test_extract_code_deps_nuclei(self):
        self.assertEqual(rg._iter_findings({'type':'code','details':{'findings':[{'type':'SQLi','severity':'critical'}]}})[0]['severity'],'critical')
        self.assertEqual(len(rg._iter_findings({'type':'deps','details':{'files':[{'vulnerabilities':[{'id':'CVE','package':'x'}]}]}})),1)
        self.assertEqual(rg._iter_findings({'type':'nuclei','target':'x','details':{'findings':[{'template_id':'t','severity':'high'}]}})[0]['severity'],'high')
    def test_network_summary(self):
        self.assertEqual(len(rg._iter_findings({'type':'network','details':{'open_ports':[80,445]}})),1); self.assertEqual(rg._summarize([])['risk'],'none')

class TestFormats(unittest.TestCase):
    def finding(self): return {'source':'X','title':'<x>','severity':'high','target':'x','description':'d','evidence':'e','fix':'f','cwe':'CWE-1','extra':{}}
    def test_markdown_html_json(self):
        f=[self.finding()]; meta={'title':'T','target':'x','date':'d'}; summary=rg._summarize(f)
        self.assertIn('# T',rg.to_markdown(meta,f,summary)); self.assertIn('&lt;x&gt;',rg.to_html(meta,f,summary)); self.assertEqual(rg.to_json(meta,f,summary)['summary']['total'],1)

class TestGenerate(unittest.TestCase):
    def test_empty_and_formats(self):
        path=history([])
        with self.assertRaises(ValueError): rg.generate_report(None,{'history_file':path})
        os.unlink(path)
    def test_flow_and_filter(self):
        path=history([{'type':'code','target':'x','details':{'findings':[{'type':'X','severity':'low'}]}},{'type':'code','target':'y','details':{'findings':[{'type':'Y','severity':'critical'}]}}])
        result=rg.generate_report(None,{'history_file':path,'format':'markdown','entry_ids':[2]}); self.assertEqual(result['summary']['total'],1); self.assertIn('Y',result['content']); os.unlink(path)

if __name__=='__main__': unittest.main(verbosity=2)
