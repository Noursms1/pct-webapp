# -*- coding: utf-8 -*-
import json
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from engine import dependency_scanner as ds


class TestParsing(unittest.TestCase):
    def test_requirements(self):
        result = ds.parse_requirements_txt('# x\nflask==3.0.0\nrequests>=2.31 ; python_version >= "3.10"\n-r base.txt\ngit+https://x/y.git#egg=z\n')
        self.assertEqual(result, [{"name": "flask", "specifier": "==3.0.0"}, {"name": "requests", "specifier": ">=2.31"}])

    def test_file_types(self):
        self.assertEqual(ds.detect_file_type('/x/requirements.txt'), 'requirements')
        self.assertEqual(ds.detect_file_type('Pipfile'), 'pipfile')
        self.assertIsNone(ds.detect_file_type('setup.cfg'))


class TestAuditParsing(unittest.TestCase):
    def test_valid_vulnerability(self):
        data = json.dumps({"dependencies": [{"name": "urllib3", "version": "1", "vulns": [{"id": "GHSA-x", "aliases": ["CVE-x"], "fix_versions": ["2"], "description": "Remote code execution"}]}]})
        result = ds._parse_pip_audit_output(data, '', 0)
        self.assertEqual(result['packages_scanned'], 1)
        self.assertEqual(result['vulnerabilities'][0]['package'], 'urllib3')

    def test_invalid_and_empty(self):
        self.assertIn('Invalid JSON', ds._parse_pip_audit_output('bad', '', 1)['error'])
        self.assertEqual(ds._parse_pip_audit_output('{"meta":{}}', '', 0)['packages_scanned'], 0)
        self.assertIn('failed', ds._parse_pip_audit_output('', 'failed', 2)['error'])


class TestAuditExecution(unittest.TestCase):
    def test_missing_tool(self):
        with mock.patch.object(ds, 'pip_audit_available', return_value=False):
            result = ds.run_pip_audit('missing.txt')
        self.assertFalse(result['available'])
        self.assertIn('not installed', result['error'])

    def test_timeout_and_success(self):
        with mock.patch.object(ds, 'pip_audit_available', return_value=True), mock.patch('subprocess.run', side_effect=ds.subprocess.TimeoutExpired('cmd', 1)):
            self.assertIn('timed out', ds.run_pip_audit('x', 1)['error'])
        proc = mock.Mock(returncode=0, stdout='{"dependencies":[]}', stderr='')
        with mock.patch.object(ds, 'pip_audit_available', return_value=True), mock.patch('subprocess.run', return_value=proc):
            self.assertIsNone(ds.run_pip_audit('x')['error'])


class TestScan(unittest.TestCase):
    def test_content_and_empty_entry(self):
        proc = mock.Mock(returncode=0, stdout='{"dependencies":[]}', stderr='')
        with mock.patch.object(ds, 'pip_audit_available', return_value=True), mock.patch('subprocess.run', return_value=proc):
            result = ds.scan_requirements_content('flask==3.0.0\n')
            self.assertEqual(result['packages_parsed'], 1)
            summary = ds.scan_dependencies(None, {'files': [{'name': 'requirements.txt', 'content': 'flask'}]})
        self.assertEqual(summary['files_scanned'], 1)
        self.assertEqual(ds.scan_dependencies(None, {})['risk_level'], 'none')

    def test_unsupported_file(self):
        result = ds.scan_dependencies(None, {'files': [{'name': 'setup.cfg', 'content': 'x'}]})
        self.assertFalse(result['files'][0]['supported'])


class TestSeverity(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(ds._guess_severity({'description': 'Remote code execution'}), 'critical')
        self.assertEqual(ds._guess_severity({'description': 'XSS issue'}), 'medium')
        self.assertEqual(ds._risk_level([]), 'none')


if __name__ == '__main__':
    unittest.main(verbosity=2)
