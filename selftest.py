#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اختبار ذاتي للمحرك (بدون سيرفر).
Self-test for the engine layer only.

    python selftest.py
"""

import sys
import os
import json
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import (
    code_reviewer, network_scanner, hash_matcher, osint_dns,
    dependency_scanner, email_recon, report_generator, nuclei_scanner,
)
from engine.core import JobManager, HistoryManager


def section(title):
    print("\n" + "=" * 60)
    print("  " + title)
    print("=" * 60)


# ===========================================================================
# 1) Code Reviewer
# ===========================================================================

def test_code_reviewer():
   def test_code_reviewer():
    section("1) Code Reviewer")
    code = """
# Secrets Manager: password = os.getenv('DB_PASSWORD')
# Parameterized Queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
# subprocess بقائمة args و shell=False: subprocess.run(['ping','-c','1',host])
import pickle
# yaml.safe_load() أو json
# textContent / Jinja2 autoescape: element.textContent = userInput;
# hashlib.sha256 / bcrypt / argon2 أو AES-GCM
"""
    r = code_reviewer.scan_code(None, {"code": code, "filename": "demo.py"})
    secret_hits = [f for f in r["findings"] if f["rule_id"] == "SECRET"]
    assert secret_hits and "SuperSecret" not in secret_hits[0]["snippet"], "secret not masked"
    print("  [OK] code reviewer + secret masking")


# ===========================================================================
# 2) Hash Matcher
# ===========================================================================

def test_hash_matcher():
    section("2) Hash Matcher")
    target = hash_matcher.hash_word("password123", "md5")
    ident = hash_matcher.detect_hash_type(target)
    print(f"  target={target} detected={ident['primary']}")
    assert ident["valid"] and ident["primary"] == "MD5"

    words = [f"word{i}" for i in range(500)] + ["password123"]
    r = hash_matcher.crack_hash(None, {"hash": target, "words": words})
    print(f"  found={r['found']} match={r['match']} tried={r['words_tried']} t={r['elapsed']}s")
    assert r["found"] and r["match"]["word"] == "password123"

    sha = hash_matcher.hash_word("admin", "sha256")
    r2 = hash_matcher.crack_hash(None, {"hash": sha, "words": ["x", "admin"]})
    assert r2["found"], "sha256 crack failed"
    gen = hash_matcher.generate_hashes("test")
    assert gen["sha256"] == hash_matcher.hash_word("test", "sha256")
    print("  [OK] md5 + sha256 matching + generator")


# ===========================================================================
# 3) Network Scanner
# ===========================================================================

def test_network_scanner():
    section("3) Network Scanner (localhost)")
    ips = network_scanner.resolve("127.0.0.1")
    print(f"  resolved: {ips}")
    open_ports, elapsed = network_scanner.scan_ports(
        "127.0.0.1", [22, 80, 443, 8000, 8080, 3306], timeout=0.4, max_threads=20)
    print(f"  open={open_ports} elapsed={elapsed}s")
    r = network_scanner.scan_network(None, {
        "target": "127.0.0.1", "mode": "custom",
        "ports": [22, 80, 443, 8000], "timeout": 0.4, "threads": 20, "banner": False,
    })
    print(f"  mode={r['mode']} scanned={r['ports_scanned']} open={r['open_count']}")
    print("  [OK] network scanner")


# ===========================================================================
# 4) OSINT
# ===========================================================================

def test_osint():
    section("4) OSINT (offline-safe)")
    r = osint_dns.run_osint(None, {
        "target": "127.0.0.1", "whois": False, "ssl": False,
        "wellknown": False, "dns_types": ["A"],
    })
    print(f"  host={r['host']} ip={r['ip']} reverse={r['reverse_dns']}")
    print(f"  http_status={r['http_status']} http_error={r['http_error']}")
    assert r["host"] == "127.0.0.1"
    audit = osint_dns.audit_security_headers({"Server": "nginx", "X-Frame-Options": "DENY"})
    print(f"  header audit: score={audit['score']} grade={audit['grade']} missing={len(audit['missing'])}")
    print("  [OK] osint")


# ===========================================================================
# 5) Job Manager + History
# ===========================================================================

def test_job_manager():
    section("5) Job Manager + History")
    tmp = os.path.join(tempfile.gettempdir(), "pct_test_history.json")
    if os.path.exists(tmp):
        os.remove(tmp)
    history = HistoryManager(tmp)
    jm = JobManager(max_workers=2, history=history)

    def slow_job(job, params):
        pr = params["_progress"]
        for i in range(10):
            pr.update((i + 1) * 10)
        return {"value": 42, "target": params.get("target")}

    j = jm.submit("code", "unit-test", slow_job, {"target": "x"})
    print(f"  submitted job {j['id']} status={j['status']}")
    import time
    for _ in range(50):
        st = jm.get(j["id"])
        if st["status"] in ("done", "error"):
            break
        time.sleep(0.1)
    assert st["status"] == "done", f"job failed: {st}"
    assert st["result"]["value"] == 42
    assert len(history.list()) == 1
    print(f"  final status={st['status']} progress={st['progress']} history={len(history.list())}")
    os.remove(tmp)
    print("  [OK] job manager + history persistence")


# ===========================================================================
# 6) Dependencies (offline — parser + graceful pip-audit)
# ===========================================================================

def test_dependencies():
    section("6) Dependency Scanner (offline)")
    content = (
        "urllib3==1.26.0\n"
        "jinja2==2.11.0\n"
        "# a comment\n"
        "\n"
        "-r other.txt\n"
        "git+https://github.com/x/y.git#egg=z\n"
    )
    pkgs = dependency_scanner.parse_requirements_txt(content)
    print(f"  parser: {len(pkgs)} packages found")
    for p in pkgs:
        print(f"     - {p['name']} {p['specifier']}")
    assert len(pkgs) == 2, f"expected 2 packages, got {len(pkgs)}"

    avail = dependency_scanner.pip_audit_available()
    print(f"  pip-audit available: {avail}")
    if avail:
        from unittest import mock
        fake = {"tool": "pip-audit", "available": True, "vulnerabilities": [], "packages_scanned": 1, "error": None}
        with mock.patch.object(dependency_scanner, "run_pip_audit", return_value=fake):
            r = dependency_scanner.scan_requirements_content("flask==3.0.0", filename="inline.txt")
        print(f"  scan (mocked): parsed={r['packages_parsed']} tool_available={r['tool_available']}")
        assert r["packages_parsed"] == 1
    else:
        r = dependency_scanner.scan_requirements_content("flask==3.0.0", filename="inline.txt")
        assert r["packages_parsed"] == 1 and r["error"]
        print(f"  graceful error: {r['error'][:60]}...")
    print("  [OK] dependency scanner")


# ===========================================================================
# 7) Email Recon (offline — parts only, no network)
# ===========================================================================

def test_email_recon():
    section("7) Email Recon (offline parts)")

    # --- validation ---
    assert email_recon.is_valid_email("user@example.com") is True
    assert email_recon.is_valid_email("bad") is False
    assert email_recon.is_valid_email("a@b") is False
    print("  validation: ok")

    # --- parsing ---
    p = email_recon.parse_email_parts("admin@mailinator.com")
    print(f"  parts: role={p['is_role_based']} disposable={p['is_disposable']}")
    assert p["is_role_based"] is True
    assert p["is_disposable"] is True
    assert p["domain"] == "mailinator.com"

    # --- full recon with all network checks disabled ---
    r = email_recon.recon_email(None, {
        "email": "test@example.com",
        "check_gravatar": False,
        "check_github": False,
        "check_breach": False,
        "check_rep": False,
        "check_domain": False,
    })
    assert r["parts"]["local"] == "test"
    assert r["parts"]["domain"] == "example.com"
    assert r["email_hash"], "email_hash missing"

    # --- privacy: raw email must NOT appear in result ---
    as_str = json.dumps(r)
    assert "test@example.com" not in as_str, "raw email leaked in result!"
    print("  privacy: raw email not exposed")
    print("  [OK] email recon")


# ===========================================================================
# 8) Report Generator (offline — temp history)
# ===========================================================================

def test_report_generator():
    section("8) Report Generator (offline)")
    tmp = os.path.join(tempfile.gettempdir(), "pct_report_test.json")
    if os.path.exists(tmp):
        os.remove(tmp)

    hm = HistoryManager(tmp)
    hm.add("code", "demo.py", "findings=1", {
        "findings": [{
            "title": "SQL Injection", "severity": "critical",
            "cwe": "CWE-89", "cvss_score": "9.8",
            "line": 3, "desc": "tainted sql",
            "snippet": "cur.execute(q)",
            "fix": "parameterized queries",
            "rule_id": "SQLI_AST", "analysis": "ast",
        }],
    })
    hm.add("network", "127.0.0.1", "open_ports=[135]", {
        "open_ports": [135, 445], "risky_ports": [135, 445],
    })

    for fmt, ext in (("markdown", "md"), ("html", "html"), ("json", "json")):
        r = report_generator.generate_report(None, {
            "history_file": tmp, "format": fmt, "last_n": 10,
        })
        print(f"  {fmt}: format={r['format']} findings={r['summary']['total']}")
        assert r["summary"]["total"] >= 2, f"{fmt}: expected 2+ findings"
        assert r["format"] == ext, f"{fmt}: expected ext {ext}"

    # markdown contains key info
    md = report_generator.generate_report(None, {
        "history_file": tmp, "format": "markdown", "last_n": 10,
    })
    assert "SQL Injection" in md["content"]
    assert "CWE-89" in md["content"]
    assert "Risky port" in md["content"] or "135" in md["content"]
    print("  markdown: includes title, CWE, port info")

    # html escaping
    html = report_generator.generate_report(None, {
        "history_file": tmp, "format": "html", "last_n": 10,
    })
    assert "<!DOCTYPE html>" in html["content"]
    print("  html: valid document structure")

    os.remove(tmp)
    print("  [OK] report generator")


# ===========================================================================
# 9) Nuclei (graceful degradation without binary)
# ===========================================================================

def test_nuclei():
    section("9) Nuclei Scanner (graceful)")
    avail = nuclei_scanner.nuclei_available()
    print(f"  binary available: {avail}")

    # JSONL parser — always offline
    sample = (
        '{"template-id":"CVE-X","info":{"severity":"critical","name":"Log4Shell"},'
        '"host":"example.com","matched-at":"https://example.com/api"}\n'
        'not json\n'
        '{"template-id":"info-tpl","info":{"severity":"info"},'
        '"host":"example.com","matched-at":"https://example.com/"}\n'
    )
    findings = nuclei_scanner._parse_nuclei_jsonl(sample)
    print(f"  jsonl parser: {len(findings)} findings (severity sorted)")
    assert len(findings) == 2
    assert findings[0]["severity"] == "critical"
    assert findings[1]["severity"] == "info"

    # graceful run without binary
    if not avail:
        r = nuclei_scanner.run_nuclei(["https://example.com"])
        assert r["available"] is False
        assert r["count"] == 0
        assert r["errors"], "expected error message"
        print(f"  graceful error: {r['errors'][0][:60]}...")
    print("  [OK] nuclei scanner")


# ===========================================================================
# RUNNER
# ===========================================================================

if __name__ == "__main__":
    test_code_reviewer()
    test_hash_matcher()
    test_network_scanner()
    test_osint()
    test_job_manager()
    test_dependencies()
    test_email_recon()
    test_report_generator()
    test_nuclei()
    print("\n" + "=" * 60)
    print("  جميع اختبارات المحرك نجحت ✔")
    print("=" * 60)