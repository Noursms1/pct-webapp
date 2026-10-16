# -*- coding: utf-8 -*-
import json
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from engine import email_recon as er


class TestGitHub(unittest.TestCase):
    SAMPLE = json.dumps({"total_count": 42, "items": [
        {"author": {"login": "alice"}, "repository": {"full_name": "alice/repo1"}},
        {"author": {"login": "alice"}, "repository": {"full_name": "alice/repo1"}},
        {"author": {"login": "bob"}, "repository": {"full_name": "org/repo2"}},
    ]})

    def test_success(self):
        with mock.patch.object(er, "http_get", return_value=(200, self.SAMPLE, None)):
            result = er.check_github_email("x@example.com")
        self.assertEqual(result["commit_count"], 42)
        self.assertEqual(result["usernames"], ["alice", "bob"])
        self.assertIn("alice/repo1", result["repos"])

    def test_rate_limited(self):
        with mock.patch.object(er, "http_get", return_value=(403, "", "HTTP 403")):
            result = er.check_github_email("x@example.com")
        self.assertFalse(result["available"])
        self.assertIn("rate limit", result["error"].lower())

    def test_no_results_and_invalid_json(self):
        with mock.patch.object(er, "http_get", return_value=(422, "", "HTTP 422")):
            self.assertEqual(er.check_github_email("x@example.com")["commit_count"], 0)
        with mock.patch.object(er, "http_get", return_value=(200, "bad", None)):
            self.assertIsNotNone(er.check_github_email("x@example.com")["error"])

    def test_allowlist(self):
        self.assertTrue(er._is_allowed_url("https://api.github.com/search/commits"))


class TestEmailRecon(unittest.TestCase):
    def test_gravatar_and_validation(self):
        with mock.patch.object(er, "http_get", return_value=(200, "", None)):
            self.assertTrue(er.check_gravatar("x@example.com")["exists"])
        with self.assertRaises(ValueError):
            er.recon_email(None, {"email": "not-an-email"})

    def test_github_result_is_integrated(self):
        github = {"source": "github", "available": True, "error": None, "commit_count": 1, "usernames": ["alice"], "repos": ["alice/r"]}
        with mock.patch.object(er, "check_gravatar", return_value={}), mock.patch.object(er, "check_github_email", return_value=github):
            result = er.recon_email(None, {"email": "x@example.com"})
        self.assertEqual(result["github"]["commit_count"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
