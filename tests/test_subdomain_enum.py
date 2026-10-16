# -*- coding: utf-8 -*-
import json
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from engine import subdomain_enum as se


class TestValidation(unittest.TestCase):
    def test_domains(self):
        for value in ("example.com", "sub.example.com", "a-b.co.uk", "Example.COM."):
            self.assertTrue(se.is_valid_domain(value))
        for value in ("", "example", "..com", "localhost", "127.0.0.1"):
            self.assertFalse(se.is_valid_domain(value))

    def test_subdomains_and_normalization(self):
        self.assertTrue(se.is_valid_subdomain("api.example.com", "example.com"))
        self.assertTrue(se.is_valid_subdomain("a.b.example.com", "example.com"))
        self.assertFalse(se.is_valid_subdomain("example.com.evil.com", "example.com"))
        self.assertEqual(se.normalize_subdomain("*.API.Example.COM."), "api.example.com")
        self.assertIsNone(se.normalize_subdomain("a b.com"))


class TestSSRF(unittest.TestCase):
    def test_private_and_public(self):
        for ip in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "::1"):
            self.assertTrue(se._is_private_ip(ip))
        self.assertFalse(se._is_private_ip("8.8.8.8"))

    def test_blocked_urls(self):
        for url in ("http://localhost/", "http://127.0.0.1/", "http://10.0.0.1/", "ftp://example.com/"):
            self.assertFalse(se._is_safe_url(url))


class TestSources(unittest.TestCase):
    def test_crt_parser(self):
        body = json.dumps([{"name_value": "api.example.com\n*.example.com", "common_name": "example.com"}])
        with mock.patch.object(se, "http_get", return_value=(200, body, None)):
            result = se.query_crt_sh("example.com")
        self.assertIn("api.example.com", result["raw"])
        self.assertIn("example.com", result["raw"])

    def test_hacker_parser(self):
        with mock.patch.object(se, "http_get", return_value=(200, "api.example.com,1.2.3.4\n", None)):
            self.assertIn("api.example.com", se.query_hackertarget("example.com")["raw"])

    def test_alienvault_parser(self):
        body = json.dumps({"passive_dns": [{"hostname": "api.example.com"}]})
        with mock.patch.object(se, "http_get", return_value=(200, body, None)):
            self.assertEqual(se.query_alienvault("example.com")["raw"], ["api.example.com"])

    def test_invalid_source_data(self):
        with mock.patch.object(se, "http_get", return_value=(200, "bad", None)):
            self.assertIsNotNone(se.query_crt_sh("example.com")["error"])
            self.assertIsNotNone(se.query_alienvault("example.com")["error"])


class TestAggregationAndProbe(unittest.TestCase):
    def test_aggregate_deduplicates_and_filters(self):
        with mock.patch.object(se, "SOURCES", {"x": lambda domain, timeout=15: {"raw": ["api.example.com", "evil.com"], "status": 200, "error": None}}):
            result = se.aggregate_sources("example.com", ["x"])
        self.assertEqual(result["subdomains"], ["api.example.com"])

    def test_source_exception_isolated(self):
        with mock.patch.object(se, "SOURCES", {"x": lambda domain, timeout=15: (_ for _ in ()).throw(RuntimeError("down"))}):
            result = se.aggregate_sources("example.com", ["x"])
        self.assertIn("down", result["sources"]["x"]["error"])

    def test_probe_private_and_exception(self):
        self.assertEqual(se.probe_one("127.0.0.1")["error"], "blocked")
        with mock.patch.object(se, "_is_safe_url", return_value=True), mock.patch("urllib.request.urlopen", side_effect=Exception("boom")):
            result = se.probe_one("example.com")
        self.assertIsNone(result["http_status"])

    def test_wildcard_detection(self):
        self.assertIn("a.b.c.example.com", se.detect_wildcards("example.com", ["a.b.c.example.com"]))


class TestEntry(unittest.TestCase):
    def test_invalid_and_basic_flow(self):
        with self.assertRaises(ValueError):
            se.enumerate_subdomains(None, {"domain": "not a domain"})
        with mock.patch.object(se, "SOURCES", {"x": lambda domain, timeout=15: {"raw": ["api.example.com"], "status": 200, "error": None}}):
            result = se.enumerate_subdomains(None, {"domain": "example.com", "sources": ["x"]})
        self.assertEqual(result["count"], 1)
        self.assertFalse(result["probe_enabled"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
