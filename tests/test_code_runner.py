import shutil
import unittest


def _docker_available() -> bool:
    """Return True only if the Docker daemon is actually reachable."""
    if shutil.which("docker") is None:
        return False
    try:
        import subprocess
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


# -*- coding: utf-8 -*-
import os, sys, subprocess, unittest
from unittest import mock
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path: sys.path.insert(0, ROOT)
from engine import code_runner as cr


@unittest.skipUnless(_docker_available(), 'Docker not available')
class TestRunner(unittest.TestCase):
    def test_config_and_validation(self):
        self.assertIn('python',cr.LANGUAGES)
        with self.assertRaises(ValueError): cr.run_code(None,{})
        with self.assertRaises(ValueError): cr.run_code(None,{'code':'x','language':'unknown'})
        with mock.patch.object(cr,'docker_available',return_value=False):
            with self.assertRaises(RuntimeError): cr.run_code(None,{'code':'print(1)'})
    def test_available_shape(self):
        with mock.patch.object(cr,'docker_available',return_value=False):
            self.assertFalse(cr.available_languages()['python']['available'])
    def test_mocked_success_error_timeout(self):
        fake=mock.Mock(returncode=0,stdout='hello',stderr='')
        with mock.patch.object(cr,'docker_available',return_value=True),mock.patch.object(cr,'image_present',return_value=True),mock.patch('subprocess.run',return_value=fake):
            self.assertEqual(cr.run_code(None,{'code':'print(1)'})['exit_code'],0)
        with mock.patch.object(cr,'docker_available',return_value=True),mock.patch.object(cr,'image_present',return_value=True),mock.patch('subprocess.run',side_effect=subprocess.TimeoutExpired('x',1)):
            self.assertFalse(cr.run_code(None,{'code':'x','timeout':1})['ok'])

if __name__=='__main__': unittest.main(verbosity=2)
