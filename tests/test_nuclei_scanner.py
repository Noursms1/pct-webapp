# -*- coding: utf-8 -*-
import json
import os
import sys
import unittest
from unittest import mock
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path: sys.path.insert(0, ROOT)
from engine import nuclei_scanner as ns

class TestBinary(unittest.TestCase):
    def test_available_and_version(self):
        with mock.patch('shutil.which', return_value='/x/nuclei'): self.assertTrue(ns.nuclei_available())
        fake=mock.Mock(stdout='Nuclei Engine Version: v3\n',stderr='')
        with mock.patch('shutil.which',return_value='/x/nuclei'),mock.patch('subprocess.run',return_value=fake): self.assertIn('Nuclei',ns.nuclei_version())

class TestTargets(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(ns._normalize_target('example.com'),'https://example.com')
        self.assertEqual(len(ns._normalize_targets(['example.com','https://example.com','http://example.com'])),2)
        self.assertIsNone(ns._normalize_target(''))

class TestParsing(unittest.TestCase):
    def test_parse_sort_dedup(self):
        lines=[json.dumps({'template-id':'low','info':{'severity':'low'},'host':'x','matched-at':'a'}),json.dumps({'template-id':'critical','info':{'severity':'critical'},'host':'x','matched-at':'b'}),json.dumps({'template-id':'low','info':{'severity':'low'},'host':'x','matched-at':'a'})]
        result=ns._parse_nuclei_jsonl('\n'.join(lines)); self.assertEqual(len(result),2); self.assertEqual(result[0]['severity'],'critical')
    def test_invalid_unknown(self):
        self.assertEqual(ns._parse_nuclei_jsonl('bad\nnull'),[])
        result=ns._parse_nuclei_jsonl(json.dumps({'template-id':'x','info':{'severity':'weird'},'host':'h'})); self.assertEqual(result[0]['severity'],'unknown')

class TestCommand(unittest.TestCase):
    def test_options(self):
        command=ns._build_cmd('/x/nuclei','/tmp/t',severity=['high','critical'],tags=['cve','rce'],rate_limit=100)
        self.assertIn('-no-interactsh',command); self.assertEqual(command[command.index('-severity')+1],'high,critical'); self.assertEqual(command[command.index('-tags')+1],'cve,rce')

class TestRunner(unittest.TestCase):
    def test_unavailable_and_empty(self):
        with mock.patch.object(ns,'nuclei_available',return_value=False): self.assertFalse(ns.run_nuclei(['example.com'])['available'])
        with mock.patch.object(ns,'nuclei_available',return_value=True),mock.patch.object(ns,'nuclei_version',return_value='v3'): self.assertTrue(ns.run_nuclei([])['errors'])
    def test_success(self):
        output=json.dumps({'template-id':'test','info':{'severity':'medium'},'host':'example.com','matched-at':'https://example.com'})+'\n'
        process=mock.Mock(); process.communicate.return_value=(output,'')
        with mock.patch.object(ns,'nuclei_available',return_value=True),mock.patch.object(ns,'nuclei_path',return_value='/x/nuclei'),mock.patch.object(ns,'nuclei_version',return_value='v3'),mock.patch('subprocess.Popen',return_value=process):
            result=ns.run_nuclei(['example.com'])
        self.assertEqual(result['count'],1); self.assertEqual(result['severity_counts'],{'medium':1})

class TestEntry(unittest.TestCase):
    def test_params(self):
        with mock.patch.object(ns,'run_nuclei',return_value={'count':0}) as runner:
            ns.scan_with_nuclei(None,{'targets':['x'],'severity':'high','rate_limit':100})
        self.assertEqual(runner.call_args.kwargs['severity'],'high'); self.assertEqual(runner.call_args.kwargs['rate_limit'],100)

if __name__=='__main__': unittest.main(verbosity=2)
