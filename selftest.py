# -*- coding: utf-8 -*-
"""
PCT - Portable Cybersecurity Toolkit
Self-test suite.

Runs smoke tests against the main engine modules and prints a clear
pass/fail summary. Exit code 0 = all good, 1 = at least one failure.

Usage:
    python selftest.py
    python selftest.py --verbose
    python selftest.py --json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import Any, Callable, List, Tuple

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

BASE_DIR = Path(__file__).parent.resolve()
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


# ---------------------------------------------------------------------------
# Minimal test harness
# ---------------------------------------------------------------------------
class Report:
    def __init__(self) -> None:
        self.rows: List[Tuple[str, str, bool, str, float]] = []

    def add(self, section: str, name: str, ok: bool, detail: str, ms: float) -> None:
        self.rows.append((section, name, ok, detail, ms))

    @property
    def passed(self) -> int:
        return sum(1 for r in self.rows if r[2])

    @property
    def failed(self) -> int:
        return sum(1 for r in self.rows if not r[2])

    @property
    def total(self) -> int:
        return len(self.rows)

    def ok(self) -> bool:
        return self.failed == 0


REPORT = Report()


def run_case(section: str, name: str, fn: Callable[[], Any]) -> None:
    start = time.perf_counter()
    ok = True
    detail = ""
    try:
        out = fn()
        if out is not None:
            detail = str(out)
    except Exception as exc:
        ok = False
        detail = "{0}: {1}".format(type(exc).__name__, exc)
        if os.environ.get("PCT_SELFTEST_TRACE"):
            detail += "\n" + traceback.format_exc()
    elapsed = (time.perf_counter() - start) * 1000.0
    REPORT.add(section, name, ok, detail, elapsed)


def section(index: int, title: str) -> None:
    line = "=" * 62
    print("")
    print(line)
    print("  {0}) {1}".format(index, title))
    print(line)


def safe_tempfile(suffix: str = ".db") -> str:
    """Create a temp file path without auto-cleanup (Windows-friendly)."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    try:
        os.unlink(path)
    except OSError:
        pass
    return path


# ---------------------------------------------------------------------------
# 1) Code reviewer
# ---------------------------------------------------------------------------
def test_code_reviewer() -> None:
    section(1, "Code Reviewer")

    def check_import() -> str:
        from engine import code_reviewer
        return "module={0}".format(code_reviewer.__name__)

    run_case("Code Reviewer", "import", check_import)

    def check_scan_vulnerable() -> str:
        from engine import code_reviewer
        sample = (
            "import os\n"
            "import pickle\n"
            "DB_PASSWORD = 'SuperSecret123!'\n"
            "cur.execute('SELECT * FROM users WHERE id = ' + user_id)\n"
            "os.system('ping -c 1 ' + host)\n"
            "obj = pickle.loads(data)\n"
            "el.innerHTML = userInput\n"
            "h = hashlib.md5(b'x').hexdigest()\n"
        )
        result = code_reviewer.scan_code(None, {"code": sample, "filename": "demo.py"})
        total = int(result.get("total_findings", 0))
        if total < 1:
            raise AssertionError("expected at least one finding, got 0")
        return "findings={0}".format(total)

    run_case("Code Reviewer", "scan vulnerable", check_scan_vulnerable)

    def check_scan_clean() -> str:
        from engine import code_reviewer
        clean = "def add(a: int, b: int) -> int:\n    return a + b\n"
        result = code_reviewer.scan_code(None, {"code": clean, "filename": "clean.py"})
        return "findings={0}".format(result.get("total_findings", 0))

    run_case("Code Reviewer", "scan clean", check_scan_clean)


# ---------------------------------------------------------------------------
# 2) Dependency scanner
# ---------------------------------------------------------------------------
def test_dependency_scanner() -> None:
    section(2, "Dependency Scanner")

    def check_parser() -> str:
        from engine import dependency_scanner
        parser = getattr(dependency_scanner, "parse_requirements_txt", None)
        if parser is None:
            raise AttributeError("parse_requirements_txt not found")
        content = "flask==0.12.0\nrequests>=2.0.0\ndjango<3.0\n"
        packages = parser(content)
        if not packages:
            raise AssertionError("parser returned empty result")
        return "packages={0}".format(len(packages))

    run_case("Dependencies", "parse requirements.txt", check_parser)


# ---------------------------------------------------------------------------
# 3) Languages registry
# ---------------------------------------------------------------------------
def test_languages() -> None:
    section(3, "Languages Registry")

    def check_reload() -> str:
        from engine import languages
        languages.reload()
        names = languages.list_names()
        if not names:
            raise AssertionError("no languages registered")
        return "count={0} first={1}".format(len(names), names[0])

    run_case("Languages", "reload + list", check_reload)

    def check_detect() -> str:
        from engine import languages
        detected = languages.detect("app.py")
        if detected != "python":
            raise AssertionError("expected python, got {0}".format(detected))
        return "detect=python"

    run_case("Languages", "detect python", check_detect)

    def check_stats() -> str:
        from engine import languages
        stats = languages.stats()
        return "languages={0} rules={1}".format(
            stats.get("languages"), stats.get("total_rules")
        )

    run_case("Languages", "stats snapshot", check_stats)


# ---------------------------------------------------------------------------
# 4) Rule engine
# ---------------------------------------------------------------------------
def test_rule_engine() -> None:
    section(4, "Rule Engine")

    def check_scan_multi() -> str:
        from engine import rule_engine
        payload = {
            "files": [
                {
                    "name": "server.py",
                    "content": (
                        "import os\n"
                        "os.system('ping ' + host)\n"
                        "password = 'hardcoded'\n"
                    ),
                }
            ]
        }
        result = rule_engine.scan_multi(None, payload)
        total = int(result.get("total_findings", 0))
        if total < 1:
            raise AssertionError("expected at least one finding")
        return "files={0} findings={1}".format(result.get("files_scanned"), total)

    run_case("Rule Engine", "scan_multi", check_scan_multi)


# ---------------------------------------------------------------------------
# 5) Unified intelligence layer
# ---------------------------------------------------------------------------
def test_unified() -> None:
    section(5, "Unified Intelligence")

    def check_db() -> str:
        from engine.unified import IntelligenceDB
        db_path = safe_tempfile(".db")
        try:
            db = IntelligenceDB(db_path)
            migrations = db.applied_migrations()
            try:
                db.close()
            except Exception:
                pass
            if not migrations:
                raise AssertionError("no migrations applied")
            return "migrations={0}".format(len(migrations))
        finally:
            try:
                os.unlink(db_path)
            except OSError:
                pass

    run_case("Unified", "IntelligenceDB init", check_db)

    def check_rule_store() -> str:
        from engine.unified import IntelligenceDB, RuleStore
        db_path = safe_tempfile(".db")
        try:
            db = IntelligenceDB(db_path)
            store = RuleStore(db)
            added = store.add({
                "id": "TEST-001",
                "title": "Test rule",
                "severity": "high",
                "languages": ["python"],
            })
            if not added:
                raise AssertionError("store.add returned False")
            fetched = store.get("TEST-001")
            if not fetched:
                raise AssertionError("rule not retrievable after add")
            try:
                db.close()
            except Exception:
                pass
            return "insert + fetch ok"
        finally:
            try:
                os.unlink(db_path)
            except OSError:
                pass

    run_case("Unified", "RuleStore add/get", check_rule_store)

    def check_correlation() -> str:
        from engine.unified import CorrelationEngine
        engine = CorrelationEngine()
        deps = {
            "vulnerabilities": [
                {"package": "flask", "id": "CVE-X", "severity": "high"}
            ]
        }
        code = {"findings": []}
        results = engine.correlate_deps_code(deps, code, "import flask")
        return "correlations={0}".format(len(results))

    run_case("Unified", "CorrelationEngine", check_correlation)


# ---------------------------------------------------------------------------
# 6) Knowledge base
# ---------------------------------------------------------------------------
def test_knowledge() -> None:
    section(6, "Knowledge Base")

    def check_upsert() -> str:
        from engine.knowledge_base import KnowledgeBase
        db_path = safe_tempfile(".db")
        try:
            kb = KnowledgeBase(db_path)
            entity_id = kb.upsert_entity("domain", "example.com", "selftest")
            if not entity_id:
                raise AssertionError("upsert_entity returned falsy id")
            stats = kb.stats()
            return "stats={0}".format(stats)
        finally:
            # Best-effort cleanup on Windows; ignore if locked
            try:
                os.unlink(db_path)
            except OSError:
                pass

    run_case("Knowledge", "upsert + stats", check_upsert)


# ---------------------------------------------------------------------------
# 7) Report generator
# ---------------------------------------------------------------------------
def test_report_generator() -> None:
    section(7, "Report Generator")

    def check_html() -> str:
        from engine import report_generator
        fn = getattr(report_generator, "to_html", None)
        if fn is None:
            raise AttributeError("report_generator.to_html not found")
        metadata = {"title": "Selftest", "target": "example.com"}
        findings = [
            {
                "severity": "high",
                "title": "Test finding",
                "target": "line 1",
                "description": "desc",
                "evidence": "snippet",
                "fix": "do X",
            }
        ]
        summary = {"total": 1, "risk": "high"}
        html = fn(metadata, findings, summary)
        if "<html" not in html.lower():
            raise AssertionError("html output looks malformed")
        return "html_len={0}".format(len(html))

    run_case("Reports", "to_html", check_html)


# ---------------------------------------------------------------------------
# 8) Server entrypoints
# ---------------------------------------------------------------------------
def test_entrypoints() -> None:
    section(8, "Server Entrypoints")

    def check_files() -> str:
        candidates = ["run_server.py", "server.py"]
        present = [name for name in candidates if (BASE_DIR / name).exists()]
        if not present:
            raise AssertionError("no server entrypoint found")
        return "present={0}".format(present)

    run_case("Runner", "entrypoints present", check_files)


# ---------------------------------------------------------------------------
# 9) AI / REA bridge (optional)
# ---------------------------------------------------------------------------
def test_ai_bridge() -> None:
    section(9, "AI / REA Bridge (optional)")

    def check_bridge_module() -> str:
        ai_dir = BASE_DIR / "ai"
        if not ai_dir.is_dir():
            raise FileNotFoundError("ai/ directory not present")
        rea_client = ai_dir / "rea_client.py"
        if not rea_client.exists():
            raise FileNotFoundError("ai/rea_client.py not present")
        return "ai/ present with rea_client.py"

    run_case("AI", "ai/ folder present", check_bridge_module)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
SECTIONS: List[Callable[[], None]] = [
    test_code_reviewer,
    test_dependency_scanner,
    test_languages,
    test_rule_engine,
    test_unified,
    test_knowledge,
    test_report_generator,
    test_entrypoints,
    test_ai_bridge,
]


def run_all(verbose: bool = False) -> Report:
    print("")
    print("#" * 62)
    print("#  PCT Self-Test")
    print("#  base dir: {0}".format(BASE_DIR))
    print("#" * 62)

    for fn in SECTIONS:
        try:
            fn()
        except Exception as exc:
            REPORT.add(
                fn.__name__, "setup", False,
                "{0}: {1}".format(type(exc).__name__, exc), 0.0,
            )

    print("")
    print("=" * 62)
    print("  RESULTS")
    print("=" * 62)
    for sec, name, ok, detail, ms in REPORT.rows:
        mark = "PASS" if ok else "FAIL"
        line = "  [{0}] {1}/{2}".format(mark, sec, name)
        if ms:
            line += " ({0:.0f}ms)".format(ms)
        print(line)
        if detail and (verbose or not ok):
            print("        {0}".format(detail))
    print("=" * 62)
    print("  TOTAL={0}  PASSED={1}  FAILED={2}".format(
        REPORT.total, REPORT.passed, REPORT.failed
    ))
    print("=" * 62)
    return REPORT


def main() -> int:
    parser = argparse.ArgumentParser(description="PCT self-test suite")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="print details for every test")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON summary")
    args = parser.parse_args()

    report = run_all(verbose=args.verbose)

    if args.json:
        payload = {
            "summary": {
                "total": report.total,
                "passed": report.passed,
                "failed": report.failed,
                "ok": report.ok(),
            },
            "results": [
                {
                    "section": sec,
                    "name": name,
                    "ok": ok,
                    "detail": detail,
                    "elapsed_ms": round(ms, 2),
                }
                for sec, name, ok, detail, ms in report.rows
            ],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))

    return 0 if report.ok() else 1


if __name__ == "__main__":
    sys.exit(main())