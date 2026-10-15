#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اختبار ذاتي للمحرك (بدون سيرفر).
Self-test for the engine layer only.

    python selftest.py
"""

import sys
import os

try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import code_reviewer, network_scanner, hash_matcher, osint_dns
from engine.core import JobManager, HistoryManager


def section(title):
    print("\n" + "=" * 60)
    print("  " + title)
    print("=" * 60)


def test_code_reviewer():
    section("1) Code Reviewer")
    code = (
        'DB_PASSWORD = "SuperSecret123!"\n'
        'cur.execute("SELECT * FROM users WHERE id = " + user_id)\n'
        'os.system("ping -c 1 " + host)\n'
        'import pickle\n'
        'obj = pickle.loads(data)\n'
        'el.innerHTML = innerHTML\n'
        'h = hashlib.md5(b"x").hexdigest()\n'
    )
    r = code_reviewer.scan_code(None, {"code": code, "filename": "demo.py"})
    print(f"  lines={r['lines']} findings={r['total_findings']} risk={r['risk_level']}")
    for f in r["findings"]:
        print(f"   - L{f['line']:<3} {f['severity']:<8} {f['type']} ({f['cwe']})")
    assert r["total_findings"] >= 5, "expected at least 5 findings"
    # التأكد من إخفاء السر
    secret_hits = [f for f in r["findings"] if f["rule_id"] == "SECRET"]
    assert secret_hits and "SuperSecret" not in secret_hits[0]["snippet"], "secret not masked"
    print("  [OK] code reviewer + secret masking")


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


def test_job_manager():
    section("5) Job Manager + History")
    import tempfile
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


if __name__ == "__main__":
    test_code_reviewer()
    test_hash_matcher()
    test_network_scanner()
    test_osint()
    test_job_manager()
    print("\n" + "=" * 60)
    print("  جميع اختبارات المحرك نجحت ✔")
    print("=" * 60)
