# -*- coding: utf-8 -*-
"""Offline Flask API tests using app.test_client()."""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
os.environ.pop("PCT_TOKEN", None)
os.environ.pop("HIBP_API_KEY", None)


class ServerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="pct_api_test_")
        import server
        self.server = server
        self.server.HISTORY_FILE = os.path.join(self.tmpdir, "scan_history.json")
        self.server.history = server.HistoryManager(self.server.HISTORY_FILE)
        self.server.jobs = server.JobManager(max_workers=2, history=self.server.history)
        self.server.API_TOKEN = None
        self.client = server.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def body(self, response):
        return json.loads(response.data.decode("utf-8"))


class TestHealthMeta(ServerTestCase):
    def test_health_rules_stats_404_index(self):
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        self.assertTrue(self.body(self.client.get("/api/health"))["ok"])
        rules = self.body(self.client.get("/api/rules"))["data"]
        self.assertIn("SQLI", {item["id"] for item in rules})
        self.assertEqual(self.body(self.client.get("/api/stats"))["data"]["total_scans"], 0)
        self.assertEqual(self.client.get("/api/missing").status_code, 404)
        self.assertEqual(self.client.get("/").status_code, 200)


class TestAuth(ServerTestCase):
    def test_token(self):
        self.server.API_TOKEN = "secret"
        self.assertEqual(self.client.post("/api/code/scan", json={"code": "x=1"}).status_code, 401)
        self.assertEqual(self.client.post("/api/code/scan", json={"code": "x=1"}, headers={"X-API-Token": "secret"}).status_code, 200)


class TestHashCode(ServerTestCase):
    def test_hash_endpoints(self):
        result = self.body(self.client.post("/api/hash/generate", json={"text": "hello"}))
        self.assertEqual(result["data"]["hashes"]["md5"], hashlib.md5(b"hello").hexdigest())
        digest = hashlib.md5(b"x").hexdigest()
        self.assertEqual(self.body(self.client.post("/api/hash/identify", json={"hash": digest}))["data"]["primary"], "MD5")
        self.assertEqual(self.client.post("/api/hash/generate", json={}).status_code, 400)

    def test_code_scan(self):
        response = self.client.post("/api/code/scan", json={"code": "os.system('x' + y)", "filename": "x.py"})
        self.assertEqual(response.status_code, 200)
        self.assertGreater(self.body(response)["data"]["total_findings"], 0)
        self.assertEqual(self.client.post("/api/code/scan", json={}).status_code, 400)


class TestJobsHistory(ServerTestCase):
    def test_jobs(self):
        self.assertEqual(self.client.post("/api/jobs", json={"type": "unknown"}).status_code, 400)
        response = self.client.post("/api/jobs", json={"type": "code", "params": {"code": "x=1"}})
        self.assertEqual(response.status_code, 202)
        job_id = self.body(response)["data"]["id"]
        for _ in range(50):
            state = self.body(self.client.get(f"/api/jobs/{job_id}"))["data"]
            if state["status"] in ("done", "error"):
                break
            time.sleep(0.05)
        self.assertEqual(state["status"], "done")
        self.assertEqual(self.client.get("/api/jobs/missing").status_code, 404)

    def test_history_auth(self):
        self.assertEqual(self.body(self.client.get("/api/history"))["data"], [])
        self.server.API_TOKEN = "secret"
        self.assertEqual(self.client.delete("/api/history").status_code, 401)
        self.assertEqual(self.client.delete("/api/history", headers={"X-API-Token": "secret"}).status_code, 200)


class TestNewEndpoints(ServerTestCase):
    def test_dependencies(self):
        with mock.patch.object(self.server.dependency_scanner, "pip_audit_available", return_value=False):
            response = self.client.post("/api/deps/scan", json={"content": "flask==3.0.0"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.body(response)["data"]["packages_parsed"], 1)
        self.assertEqual(self.client.post("/api/deps/scan", json={}).status_code, 400)

    def test_subdomains(self):
        fake = {"domain": "example.com", "subdomains": ["api.example.com"], "count": 1, "wildcards": [], "sources": {}, "probes": [], "probe_enabled": False}
        with mock.patch.object(self.server.subdomain_enum, "enumerate_subdomains", return_value=fake):
            response = self.client.post("/api/subdomains/enum", json={"domain": "example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.body(response)["data"]["count"], 1)
        self.assertEqual(self.client.post("/api/subdomains/enum", json={}).status_code, 400)

    def test_email(self):
        response = self.client.post("/api/email/recon", json={"email": "test@example.com", "check_gravatar": False, "check_github": False, "check_breach": False, "check_rep": False, "check_domain": False})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.body(response)["data"]["parts"]["domain"], "example.com")
        self.assertEqual(self.client.post("/api/email/recon", json={}).status_code, 400)

    def test_nuclei(self):
        info = self.body(self.client.get("/api/nuclei/info"))["data"]
        self.assertIn("available", info)
        with mock.patch.object(self.server.nuclei_scanner, "nuclei_available", return_value=False):
            response = self.client.post("/api/nuclei/scan", json={"targets": ["https://example.com"]})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.body(response)["data"]["available"])

    def test_reports(self):
        formats = self.body(self.client.get("/api/report/formats"))["data"]
        self.assertIn("markdown", {item["id"] for item in formats})
        self.assertEqual(self.client.post("/api/report/generate", json={"format": "markdown"}).status_code, 400)
        self.server.history.add("code", "x.py", "findings=1", {"findings": [{"title": "SQLi", "severity": "critical"}]})
        response = self.client.post("/api/report/generate", json={"format": "markdown"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("SQLi", self.body(response)["data"]["content"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
