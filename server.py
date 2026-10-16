#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 Portable Cybersecurity Toolkit - Web Server (API Layer)
-----------------------------------------------------------------------------
 PCT (Portable Cybersecurity Toolkit) - REST API server + Web UI.

 Run:
     python server.py                      # http://127.0.0.1:8000
     python server.py --host 0.0.0.0 --port 8080
     python server.py --token SECRET       # require API token

 Endpoints:
     GET    /                       -> Web UI
     GET    /api/health             -> Health check
     GET    /api/rules              -> Code review rules metadata
     GET    /api/stats              -> Aggregate statistics
     POST   /api/jobs               -> Create async job {type, params}
     GET    /api/jobs               -> List jobs
     GET    /api/jobs/<id>          -> Job details
     POST   /api/jobs/<id>/cancel   -> Cancel a job
     GET    /api/history            -> List history
     GET    /api/history/<id>       -> History entry
     DELETE /api/history            -> Clear history
     POST   /api/hash/generate      -> Generate hashes
     POST   /api/hash/identify      -> Identify hash type
     POST   /api/code/scan          -> Static code review
     POST   /api/deps/scan          -> Dependency scan
     POST   /api/subdomains/enum    -> Subdomain enumeration
     POST   /api/email/recon        -> Email OSINT
     POST   /api/nuclei/scan        -> Nuclei scan
     GET    /api/nuclei/info        -> Nuclei availability
     GET    /api/report/formats     -> Report formats
     POST   /api/report/generate    -> Generate report
     GET    /api/run/languages      -> Available execution languages
     POST   /api/run                -> Sandboxed code execution
     GET    /api/rules/languages    -> Available rule packs
     GET    /api/rules/pdf/status   -> PDF rules status
     POST   /api/rules/scan         -> Rule-based code scan
     GET    /api/doctor/check       -> Diagnostic checks
     GET    /api/system/health      -> System health snapshot
     POST   /api/orchestrate        -> Multi-module orchestration
     GET    /api/kb/stats           -> Knowledge base stats
     GET    /api/kb/entities        -> Query entities
     POST   /api/kb/annotate        -> Add annotation

 WARNING: Use this tool only against systems you are authorized to test.
=============================================================================
"""

import os
import sys
import json
import argparse
import functools

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

from flask import Flask, request, jsonify, send_from_directory

# --------------------------------------------------------------------------- #
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import JobManager, HistoryManager
from engine.core import Progress
from engine import code_reviewer, network_scanner, hash_matcher
from engine import osint_dns
from engine import dependency_scanner
from engine import subdomain_enum
from engine import email_recon
from engine import nuclei_scanner
from engine import report_generator
from engine.unified import IntelligenceDB, RuleStore, CorrelationEngine, SuggestionEngine, UnifiedScanner
from engine import correlation
from engine.knowledge_base import KnowledgeBase
from engine import code_runner
from ai.rea_client import REAClient, REA_TOOLS
from engine import language_rules, pdf_rules, rules_store, rule_engine
from engine import languages
from scan_multi import scan_multi as scan_multi_files

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
HISTORY_FILE = os.path.join(BASE_DIR, "scan_history.json")

app = Flask(__name__, static_folder=None)
app.config["JSON_AS_ASCII"] = False

history = HistoryManager(HISTORY_FILE)
jobs = JobManager(max_workers=4, history=history)
RULES_STORE = rules_store.RulesStore(os.path.join(BASE_DIR, 'rules.db'))
KNOWLEDGE = KnowledgeBase(os.path.join(BASE_DIR, 'knowledge.db'))

API_TOKEN = None  # module-level token, set in main()

import time
_RATE_BUCKETS = {}


def rate_limit(limit, window, name):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            key = (name, request.remote_addr or "local")
            now = time.time()
            bucket = _RATE_BUCKETS.setdefault(key, [])
            _RATE_BUCKETS[key] = [stamp for stamp in bucket if now - stamp < window]
            if len(_RATE_BUCKETS[key]) >= limit:
                return fail("Rate limit exceeded. Try again later.", 429)
            _RATE_BUCKETS[key].append(now)
            return fn(*args, **kwargs)
        return wrapped
    return decorator


# ===========================================================================
# Job Runners
# ===========================================================================

def _prepare(params, job):
    """
    Prepare job parameters. Currently a simple pass-through.
    Original implementation delegated to JobManager / Progress in
    engine/core.py.
    """
    return dict(params or {})


def run_code(job, params):
    return code_reviewer.scan_code(job, _prepare(params, job))


def run_network(job, params):
    return network_scanner.scan_network(job, _prepare(params, job))


def run_osint(job, params):
    return osint_dns.run_osint(job, _prepare(params, job))


def run_hash(job, params):
    if params.get("wordlist"):
        return hash_matcher.crack_hash_from_file(job, _prepare(params, job))
    return hash_matcher.crack_hash(job, _prepare(params, job))


def run_dependencies(job, params):
    return dependency_scanner.scan_dependencies(job, _prepare(params, job))


def run_subdomains(job, params):
    return subdomain_enum.enumerate_subdomains(job, _prepare(params, job))


def run_email(job, params):
    return email_recon.recon_email(job, _prepare(params, job))


def run_nuclei(job, params):
    return nuclei_scanner.scan_with_nuclei(job, _prepare(params, job))


def run_multi_scan(job, params):
    return scan_multi_files(job, _prepare(params, job))


def run_code_exec(job, params):
    return code_runner.run_code(job, _prepare(params, job))


JOB_RUNNERS = {
    "code": (run_code, lambda p: (p.get("filename") or "inline_code")),
    "network": (run_network, lambda p: p.get("target", "")),
    "osint": (run_osint, lambda p: p.get("target", "")),
    "hash": (run_hash, lambda p: (p.get("hash", "")[:16] + "...")),
    "deps": (run_dependencies, lambda p: p.get("path") or ((p.get("files") or [{}])[0].get("name", "inline"))),
    "subdomains": (run_subdomains, lambda p: p.get("domain", "")),
    "email": (run_email, lambda p: p.get("email", "")),
    "nuclei": (run_nuclei, lambda p: (p.get("targets") or ["?"])[0]
               if isinstance(p.get("targets"), list) else str(p.get("targets") or "?")),
    "multi": (run_multi_scan, lambda p: f"{len(p.get('files') or [])} files"),
    "run": (run_code_exec, lambda p: p.get("language") or "python"),
}


# ===========================================================================
# Auth / Helpers
# ===========================================================================

def require_token(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if API_TOKEN:
            supplied = request.headers.get("X-API-Token") or request.args.get("token")
            if supplied != API_TOKEN:
                return jsonify({"ok": False, "error": "Unauthorized"}), 401
        return fn(*a, **kw)
    return wrapper


def ok(data, **extra):
    payload = {"ok": True, "data": data}
    payload.update(extra)
    return jsonify(payload)


def fail(msg, code=400):
    return jsonify({"ok": False, "error": str(msg)}), code


# ===========================================================================
# UI
# ===========================================================================

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory(STATIC_DIR, path)


# ===========================================================================
# Meta API
# ===========================================================================

@app.route("/api/health")
def health():
    return ok({
        "status": "up",
        "engine": "PCT Engine 2.0",
        "active_jobs": jobs.active_count(),
        "history_entries": len(history.list(limit=10000)),
        "auth_required": bool(API_TOKEN),
    })


@app.route("/api/rules")
def rules():
    return ok(code_reviewer.rules_metadata())


@app.route("/api/stats")
def stats():
    entries = history.list(limit=10000)
    by_type = {}
    for e in entries:
        by_type[e["type"]] = by_type.get(e["type"], 0) + 1
    return ok({
        "total_scans": len(entries),
        "by_type": by_type,
        "active_jobs": jobs.active_count(),
        "common_ports": network_scanner.COMMON_PORTS,
        "risky_ports": sorted(network_scanner.RISKY_PORTS),
        "port_services": network_scanner.PORT_SERVICES,
        "security_headers": list(osint_dns.SECURITY_HEADERS.keys()),
    })


# ===========================================================================
# Jobs API
# ===========================================================================

@app.route("/api/jobs", methods=["POST"])
@require_token
def create_job():
    body = request.get_json(silent=True) or {}
    job_type = (body.get("type") or "").lower()
    params = body.get("params") or {}

    if job_type not in JOB_RUNNERS:
        return fail(f"Unknown job type: {job_type}", 400)

    func, target_fn = JOB_RUNNERS[job_type]
    try:
        target = target_fn(params)
    except Exception:
        target = "unknown"

    job = jobs.submit(job_type, target, func, params)
    return ok(job, job_id=job["id"]), 202


@app.route("/api/jobs")
def list_jobs():
    return ok(jobs.list())


@app.route("/api/jobs/<job_id>")
def get_job(job_id):
    job = jobs.get(job_id, with_result=True)
    if job is None:
        return fail("Job not found", 404)
    return ok(job)


@app.route("/api/jobs/<job_id>/cancel", methods=["POST"])
def cancel_job(job_id):
    if jobs.cancel(job_id):
        return ok({"cancelled": job_id})
    return fail("Could not cancel job", 400)


# ===========================================================================
# History API
# ===========================================================================

@app.route("/api/history")
def get_history():
    limit = min(int(request.args.get("limit", 100)), 1000)
    return ok(history.list(limit=limit))


@app.route("/api/history/<int:entry_id>")
def get_history_entry(entry_id):
    entry = history.get(entry_id)
    if entry is None:
        return fail("History entry not found", 404)
    return ok(entry)


@app.route("/api/history", methods=["DELETE"])
@require_token
def clear_history():
    history.clear()
    return ok({"cleared": True})


# ===========================================================================
# Synchronous Helpers
# ===========================================================================

@app.route("/api/hash/generate", methods=["POST"])
def hash_generate():
    body = request.get_json(silent=True) or {}
    text = body.get("text", "")
    if not text:
        return fail("text is required")
    return ok({"text": text, "hashes": hash_matcher.generate_hashes(text)})


@app.route("/api/hash/identify", methods=["POST"])
def hash_identify():
    body = request.get_json(silent=True) or {}
    h = (body.get("hash") or "").strip()
    if not h:
        return fail("hash is required")
    return ok(hash_matcher.detect_hash_type(h))


@app.route("/api/code/scan", methods=["POST"])
@require_token
def code_scan_sync():
    body = request.get_json(silent=True) or {}
    code = body.get("code")
    if not code and not body.get("files"):
        return fail("code or files is required")
    try:
        result = code_reviewer.scan_code(None, {
            "code": code,
            "files": body.get("files") or [],
            "filename": body.get("filename"),
        })
    except Exception as e:
        return fail(e)
    entry = history.add(
        "code",
        body.get("filename") or "inline_code",
        f"lines={result['lines']}, findings={result['total_findings']}",
        result,
    )
    result["entry_id"] = entry["id"]
    return ok(result)


@app.route("/api/deps/scan", methods=["POST"])
@require_token
def deps_scan_sync():
    body = request.get_json(silent=True) or {}
    content = body.get("content")
    files = body.get("files")
    if not content and not files:
        return fail("content or files is required")
    try:
        if content:
            result = dependency_scanner.scan_requirements_content(
                content, filename=body.get("filename", "inline_requirements.txt"))
        else:
            result = dependency_scanner.scan_dependencies(None, {"files": files})
    except Exception as exc:
        return fail(exc)
    target = body.get("filename") or (files[0].get("name") if files else "inline")
    entry = history.add(
        "deps", target,
        f"files={result.get('files_scanned', 0)}, vulns={result.get('vulnerabilities_total', 0)}",
        result,
    )
    result["entry_id"] = entry["id"]
    return ok(result)


@app.route("/api/subdomains/enum", methods=["POST"])
@require_token
def subdomains_enum_sync():
    body = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip()
    if not domain:
        return fail("domain is required")
    try:
        result = subdomain_enum.enumerate_subdomains(None, {
            "domain": domain,
            "sources": body.get("sources"),
            "probe_http": bool(body.get("probe_http", False)),
            "timeout": int(body.get("timeout", 15)),
            "probe_timeout": int(body.get("probe_timeout", 5)),
        })
    except Exception as exc:
        return fail(exc)
    entry = history.add("subdomains", domain, f"count={result.get('count', 0)}", result)
    result["entry_id"] = entry["id"]
    return ok(result)


@app.route("/api/email/recon", methods=["POST"])
@require_token
def email_recon_sync():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip()
    if not email:
        return fail("email is required")
    try:
        result = email_recon.recon_email(None, {
            "email": email,
            "check_gravatar": bool(body.get("check_gravatar", True)),
            "check_github": bool(body.get("check_github", True)),
            "check_breach": bool(body.get("check_breach", True)),
            "check_rep": bool(body.get("check_rep", True)),
            "check_domain": bool(body.get("check_domain", True)),
        })
        entry = history.add(
            "email",
            result.get("email_hash") or email[:16],
            f"breaches={result.get('breaches', {}).get('count', 0)}",
            result,
        )
        result["entry_id"] = entry["id"]
        return ok(result)
    except Exception as exc:
        return fail(exc)


@app.route("/api/nuclei/scan", methods=["POST"])
@require_token
def nuclei_scan_sync():
    body = request.get_json(silent=True) or {}
    if not body.get("targets"):
        return fail("targets is required")
    try:
        result = nuclei_scanner.scan_with_nuclei(None, body)
        targets = body.get("targets")
        target = targets[0] if isinstance(targets, list) and targets else str(targets or "?")
        entry = history.add("nuclei", target, f"count={result.get('count', 0)}", result)
        result["entry_id"] = entry["id"]
        return ok(result)
    except Exception as exc:
        return fail(exc)


@app.route("/api/nuclei/info")
def nuclei_info():
    return ok({
        "available": nuclei_scanner.nuclei_available(),
        "path": nuclei_scanner.nuclei_path(),
        "version": nuclei_scanner.nuclei_version(),
    })


@app.route("/api/report/formats")
def report_formats():
    return ok([
        {"id": "html", "label": "HTML"},
        {"id": "markdown", "label": "Markdown"},
        {"id": "json", "label": "JSON"},
    ])


@app.route("/api/report/generate", methods=["POST"])
@require_token
def report_generate():
    body = request.get_json(silent=True) or {}
    try:
        return ok(report_generator.generate_report(None, {
            "history_file": HISTORY_FILE,
            "entry_ids": body.get("entry_ids"),
            "last_n": int(body.get("last_n", 20)),
            "target": body.get("target"),
            "title": body.get("title"),
            "format": body.get("format", "html"),
        }))
    except Exception as exc:
        return fail(exc)


@app.route("/api/run/languages")
@rate_limit(60, 60, "run_langs")
def run_languages():
    return ok(code_runner.available_languages())


@app.route("/api/run", methods=["POST"])
@require_token
@rate_limit(10, 60, "run_code")
def run_code_sync():
    body = request.get_json(silent=True) or {}
    code = body.get("code")
    files = body.get("files")
    if not code and not files:
        return fail("code or files is required")
    if not body.get("i_am_authorized"):
        return fail("You must confirm authorization to run code")
    try:
        result = code_runner.run_code(None, {
            "code": code,
            "files": files,
            "entry": body.get("entry"),
            "language": body.get("language", "python"),
            "timeout": body.get("timeout", 30),
            "memory_mb": body.get("memory_mb", 512),
            "cpus": body.get("cpus", 1.0),
            "max_output": body.get("max_output", 4 * 1024 * 1024),
            "analyze": bool(body.get("analyze", True)),
        })
    except Exception as exc:
        return fail(exc)
    entry = history.add(
        "run",
        body.get("entry") or body.get("language", "python"),
        f"files={result.get('file_count', 1)}, exit={result.get('exit_code')}",
        {
            "language": body.get("language", "python"),
            "mode": result.get("mode"),
            "exit_code": result.get("exit_code"),
            "elapsed": result.get("elapsed"),
            "file_count": result.get("file_count"),
            "sast_total": (result.get("sast") or {}).get("total", 0),
        },
    )
    result["entry_id"] = entry["id"]
    return ok(result)


@app.route("/api/rules/languages")
@require_token
def rules_languages():
    return ok(language_rules.all_packs_metadata())


@app.route("/api/rules/pdf/status")
@require_token
def rules_pdf_status():
    return ok({
        "pypdf_available": pdf_rules.pdf_available(),
        "store": RULES_STORE.stats(),
    })


@app.route("/api/rules/scan", methods=["POST"])
@require_token
def rules_scan():
    body = request.get_json(silent=True) or {}
    files = body.get("files") or []
    if not files:
        return fail("files is required")
    try:
        return ok(scan_multi_files(None, {
            "files": files,
            "language": body.get("language"),
            "frameworks": body.get("frameworks"),
            "branch": body.get("branch"),
            "include_engineering": body.get("include_engineering", True),
        }))
    except Exception as exc:
        return fail(exc)


@app.route("/api/agent-ai", methods=["POST"])
@require_token
def agent_ai():
    body = request.get_json(silent=True) or {}
    files = body.get("files") or []
    if not isinstance(files, list) or not files:
        return fail("files is required")
    if len(files) > 50:
        return fail("maximum 50 files are allowed")
    normalized = []
    for item in files:
        if not isinstance(item, dict):
            return fail("each file must be an object")
        content = item.get("content") or ""
        if len(content) > 2 * 1024 * 1024:
            return fail("each file must be smaller than 2 MB")
        normalized.append({"name": str(item.get("name") or "unnamed"), "content": str(content)})
    try:
        result = scan_multi_files(None, {
            "files": normalized,
            "include_engineering": True,
            "frameworks": body.get("frameworks"),
            "branch": body.get("branch"),
        })
        stats = result.get("severity_stats", {})
        if stats.get("critical", 0):
            risk = "critical"
        elif stats.get("high", 0):
            risk = "high"
        elif stats.get("medium", 0):
            risk = "medium"
        elif stats.get("low", 0):
            risk = "low"
        else:
            risk = "none"
        recommendations = []
        if stats.get("critical"):
            recommendations.append("عالج الثغرات الحرجة أولاً، خصوصاً تنفيذ الأوامر وحقن SQL وفك التسلسل غير الآمن.")
        if stats.get("high"):
            recommendations.append("راجع الأسرار المضمنة وXSS ومسارات الملفات، وانقل الأسرار إلى متغيرات بيئة آمنة.")
        if stats.get("medium"):
            recommendations.append("حدّث التشفير والتحقق من TLS واستخدم مصادر عشوائية آمنة.")
        if not recommendations:
            recommendations.append("لم تظهر مخاطر معروفة بالقواعد الحالية؛ أضف اختبارات أمنية ومراجعة بشرية قبل النشر.")
        result.update({
            "prompt": str(body.get("prompt") or ""),
            "risk_level": risk,
            "recommendations": recommendations,
        })
        return ok(result)
    except Exception as exc:
        return fail(exc)


@app.route("/api/rea/status")
def rea_status():
    try:
        client = REAClient(timeout=5)
        tools = client.list_tools()
        return ok({"available": True, "tools_count": len(tools), "port": client.base_url.rsplit(":", 1)[-1]})
    except Exception as exc:
        return ok({"available": False, "error": str(exc), "port": os.getenv("REA_BRIDGE_PORT", "7801")})


@app.route("/api/rea/tools")
@require_token
def rea_tools():
    try:
        return ok(REAClient().list_tools())
    except Exception as exc:
        return fail(exc, 503)


@app.route("/api/agent-chat", methods=["POST"])
@require_token
def agent_chat():
    body = request.get_json(silent=True) or {}
    message = str(body.get("message") or "").strip()
    if not message:
        return fail("message is required")
    suggestions = [
        "ارفع ملفات ثم استخدم Agent AI للفحص متعدد اللغات.",
        "استخدم زر REA Tools لتحليل ملف تنفيذي مصرح به.",
        "استخدم Rule Library لإضافة قاعدة بعد مراجعتها.",
        "أرسل الكود إلى المشغل بعد تأكيد التصريح.",
    ]
    return ok({"reply": f"فهمت طلبك: {message}", "actions": suggestions, "rea_capabilities": list(REA_TOOLS)})


@app.route("/api/rea/call", methods=["POST"])
@require_token
def rea_call():
    body = request.get_json(silent=True) or {}
    tool = str(body.get("tool") or "").strip()
    arguments = body.get("arguments") or {}
    if tool not in REA_TOOLS:
        return fail("unsupported REA tool")
    if tool in {"annotate_native_function"} and not body.get("confirmed"):
        return fail("explicit confirmation is required for annotation", 409)
    try:
        result = REAClient(timeout=300).call_tool(tool, arguments, confirmed=bool(body.get("confirmed")))
        return ok({"tool": tool, "purpose": REA_TOOLS[tool], "result": result})
    except Exception as exc:
        return fail(exc, 503)


@app.route("/api/rules/catalog")
def rules_catalog():
    return ok({"languages": language_rules.all_packs_metadata(), "custom": RULES_STORE.list_rules(enabled_only=False)})


@app.route("/api/rules/custom", methods=["POST"])
@require_token
def add_custom_rule():
    body = request.get_json(silent=True) or {}
    required = ("id", "name", "language", "severity", "pattern_raw")
    if any(not body.get(key) for key in required):
        return fail("id, name, language, severity and pattern_raw are required")
    if not body.get("confirmed"):
        return fail("confirm rule review before saving", 409)
    try:
        added = RULES_STORE.add_rule({
            "id": body["id"], "name": body["name"], "language": body["language"],
            "severity": body["severity"], "cwe": body.get("cwe"),
            "pattern_raw": body["pattern_raw"], "desc": body.get("description", ""),
            "fix": body.get("fix", ""),
        })
        return ok({"added": bool(added), "rule": body})
    except Exception as exc:
        return fail(exc)


@app.route("/api/rules/custom/<rule_id>", methods=["PATCH"])
@require_token
def toggle_custom_rule(rule_id):
    body = request.get_json(silent=True) or {}
    if not body.get("confirmed"):
        return fail("confirm rule change", 409)
    RULES_STORE.set_rule_enabled(rule_id, bool(body.get("enabled", True)))
    return ok({"rule_id": rule_id, "enabled": bool(body.get("enabled", True))})


@app.route("/api/rules/custom/<rule_id>", methods=["DELETE"])
@require_token
def delete_custom_rule(rule_id):
    body = request.get_json(silent=True) or {}
    if not body.get("confirmed"):
        return fail("confirm rule deletion", 409)
    RULES_STORE.delete_rule(rule_id)
    return ok({"deleted": rule_id})


@app.route("/api/doctor/check")
@require_token
def doctor_check():
    import importlib.util
    path = os.path.join(BASE_DIR, "scripts", "doctor.py")
    if not os.path.exists(path):
        return fail("scripts/doctor.py not found")
    spec = importlib.util.spec_from_file_location("pct_doctor", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    d = mod.Doctor()
    d.run_checks()
    return ok(d.to_dict())


@app.route("/api/system/health")
@require_token
def system_health():
    from engine import languages
    return ok({
        "status": "healthy",
        "history_entries": len(history.list(limit=10000)),
        "active_jobs": jobs.active_count(),
        "languages": languages.stats(),
        "tools": {
            "docker": code_runner.docker_available(),
            "nuclei": nuclei_scanner.nuclei_available(),
            "pip_audit": dependency_scanner.pip_audit_available(),
        },
    })


@app.route("/api/orchestrate", methods=["POST"])
@require_token
def orchestrate():
    body = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()
    if not target:
        return fail("target is required")
    result = {"target": target, "modules_run": [], "errors": [], "results": {}}
    if "dns" in (body.get("modules") or ["dns"]):
        try:
            result["results"]["dns"] = osint_dns.dns_records(target)
            result["modules_run"].append("dns")
        except Exception as exc:
            result["errors"].append(f"dns: {exc}")
    result["correlation"] = {"findings": [], "total": 0, "risk": "none"}
    return ok(result)


@app.route("/api/kb/stats")
@require_token
def kb_stats():
    return ok(KNOWLEDGE.stats())


@app.route("/api/kb/entities")
@require_token
def kb_entities():
    return ok(KNOWLEDGE.find_entities(
        request.args.get("type"),
        request.args.get("q"),
        min(int(request.args.get("limit", 100)), 500),
    ))


@app.route("/api/kb/annotate", methods=["POST"])
@require_token
def kb_annotate():
    body = request.get_json(silent=True) or {}
    value = (body.get("value") or "").strip()
    note = (body.get("note") or "").strip()
    if not value or not note:
        return fail("value and note are required")
    return ok({
        "annotation_id": KNOWLEDGE.add_annotation(
            body.get("type", "target"), value, note, body.get("author")
        )
    })


# ===========================================================================
# Error Handlers
# ===========================================================================

@app.route("/api/unified/scan", methods=["POST"])
@require_token
def unified_scan():
    body=request.get_json(silent=True) or {}; target=(body.get("target") or "").strip(); modules=body.get("modules") or []
    if not target:return fail("target is required")
    if not isinstance(modules,list) or not modules:return fail("modules must be a non-empty list")
    try:
        scanner=UnifiedScanner(CorrelationEngine(),SuggestionEngine())
        return ok(scanner.scan(target,modules,body.get("options") or {}))
    except Exception as exc:return fail(exc)

@app.route("/api/unified/suggest", methods=["POST"])
@require_token
def unified_suggest():
    body=request.get_json(silent=True) or {}; return ok(SuggestionEngine().suggest(body.get("correlations") or []))

@app.route("/api/unified/rules/stats")
def unified_rules_stats():
    db = IntelligenceDB(os.path.join(BASE_DIR, "pct_intelligence.db"))
    store = RuleStore(db)
    stats = {
        "rules": store.count(),
        "migrations": len(db.applied_migrations()),
        "target": 3000,
    }
    return ok(stats)
@app.errorhandler(404)
def not_found(e):
    return jsonify({"ok": False, "error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"ok": False, "error": "Internal server error"}), 500


# ===========================================================================
# Entry Point
# ===========================================================================

def main():
    global API_TOKEN
    parser = argparse.ArgumentParser(
        description="Portable Cybersecurity Toolkit - Web Server")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000,
                        help="Bind port (default: 8000)")
    parser.add_argument("--token", default=os.getenv("PCT_TOKEN", ""),
                        help="API token to protect endpoints (or env PCT_TOKEN)")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    API_TOKEN = args.token or None

    print("=" * 62)
    print("  PCT - Portable Cybersecurity Toolkit  |  Web Server v2.0")
    print("=" * 62)
    print(f"  UI       : http://{args.host}:{args.port}/")
    print(f"  API      : http://{args.host}:{args.port}/api/health")
    print(f"  History  : {HISTORY_FILE}")
    print(f"  Auth     : {'enabled' if API_TOKEN else 'disabled'}")
    print("=" * 62)

    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()