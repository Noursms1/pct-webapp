#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 Portable Cybersecurity Toolkit - Web Server (API Layer)
-----------------------------------------------------------------------------
 سيرفر واجهة برمجية (REST API) يشغّل محرك PCT ويعرض واجهة ويب.

 التشغيل / Run:
     python server.py                      # http://127.0.0.1:8000
     python server.py --host 0.0.0.0 --port 8080
     python server.py --token SECRET       # حماية الـ API بتوكن

 Endpoints:
     GET    /                       -> الواجهة الرسومية
     GET    /api/health             -> حالة السيرفر
     GET    /api/rules              -> قواعد تحليل الأكواد
     GET    /api/stats              -> إحصاءات عامة
     POST   /api/jobs               -> إنشاء مهمة فحص {type, params}
     GET    /api/jobs               -> قائمة المهام
     GET    /api/jobs/<id>          -> حالة/نتيجة مهمة
     POST   /api/jobs/<id>/cancel   -> إلغاء مهمة
     GET    /api/history            -> سجل الفحوصات
     GET    /api/history/<id>       -> تفاصيل فحص
     DELETE /api/history            -> تفريغ السجل
     POST   /api/hash/generate      -> توليد هاشات لنص
     POST   /api/hash/identify      -> كشف نوع هاش
     POST   /api/code/scan          -> فحص كود مباشر (متزامن)
=============================================================================
"""

import os
import sys
import json
import argparse
import functools

try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

from flask import Flask, request, jsonify, send_from_directory

# --- استيراد المحرك -------------------------------------------------------- #
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import JobManager, HistoryManager
from engine.core import Progress
from engine import code_reviewer, network_scanner, hash_matcher
from engine import osint_dns
from engine import dependency_scanner
from engine import subdomain_enum
from engine import email_recon

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
HISTORY_FILE = os.path.join(BASE_DIR, "scan_history.json")

app = Flask(__name__, static_folder=None)
app.config["JSON_AS_ASCII"] = False

history = HistoryManager(HISTORY_FILE)
jobs = JobManager(max_workers=4, history=history)

API_TOKEN = None

# ===========================================================================
# Job Runners / مشغّلات المهام
# ===========================================================================

def _prepare(params, job):
    """
    نسخة من الـ params فقط: JobManager يحقن _progress و _stop_event تلقائياً
    عند تشغيل المهمة (انظر engine/core.py).
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


JOB_RUNNERS = {
    "code": (run_code, lambda p: (p.get("filename") or "inline_code")),
    "network": (run_network, lambda p: p.get("target", "")),
    "osint": (run_osint, lambda p: p.get("target", "")),
    "hash": (run_hash, lambda p: (p.get("hash", "")[:16] + "...")),
    "deps": (run_dependencies, lambda p: p.get("path") or ((p.get("files") or [{}])[0].get("name", "inline"))),
    "subdomains": (run_subdomains, lambda p: p.get("domain", "")),
    "email": (run_email, lambda p: p.get("email", "")),
}


# ===========================================================================
# Auth / CSRF-free token check
# ===========================================================================

def require_token(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if API_TOKEN:
            supplied = request.headers.get("X-API-Token") or request.args.get("token")
            if supplied != API_TOKEN:
                return jsonify({"ok": False, "error": "توكن غير صالح"}), 401
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
        return fail(f"نوع مهمة غير معروف: {job_type}", 400)

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
        return fail("مهمة غير موجودة", 404)
    return ok(job)


@app.route("/api/jobs/<job_id>/cancel", methods=["POST"])
def cancel_job(job_id):
    if jobs.cancel(job_id):
        return ok({"cancelled": job_id})
    return fail("لا يمكن إلغاء المهمة (غير موجودة أو منتهية)", 400)


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
        return fail("السجل غير موجود", 404)
    return ok(entry)


@app.route("/api/history", methods=["DELETE"])
@require_token
def clear_history():
    history.clear()
    return ok({"cleared": True})


# ===========================================================================
# Synchronous helpers / أدوات متزامنة سريعة
# ===========================================================================

@app.route("/api/hash/generate", methods=["POST"])
def hash_generate():
    body = request.get_json(silent=True) or {}
    text = body.get("text", "")
    if not text:
        return fail("النص مطلوب")
    return ok({"text": text, "hashes": hash_matcher.generate_hashes(text)})


@app.route("/api/hash/identify", methods=["POST"])
def hash_identify():
    body = request.get_json(silent=True) or {}
    h = (body.get("hash") or "").strip()
    if not h:
        return fail("الهاش مطلوب")
    return ok(hash_matcher.detect_hash_type(h))


@app.route("/api/code/scan", methods=["POST"])
@require_token
def code_scan_sync():
    body = request.get_json(silent=True) or {}
    code = body.get("code")
    if not code and not body.get("files"):
        return fail("لا يوجد كود لتحليله")
    try:
        result = code_reviewer.scan_code(None, {
            "code": code,
            "files": body.get("files") or [],
            "filename": body.get("filename"),
        })
    except Exception as e:
        return fail(e)
    history.add("code", body.get("filename") or "inline_code",
                f"lines={result['lines']}, findings={result['total_findings']}",
                result)
    return ok(result)


@app.route("/api/deps/scan", methods=["POST"])
@require_token
def deps_scan_sync():
    body = request.get_json(silent=True) or {}
    content = body.get("content")
    files = body.get("files")
    if not content and not files:
        return fail("لا يوجد محتوى لفحصه")
    try:
        if content:
            result = dependency_scanner.scan_requirements_content(
                content, filename=body.get("filename", "inline_requirements.txt"))
        else:
            result = dependency_scanner.scan_dependencies(None, {"files": files})
    except Exception as exc:
        return fail(exc)
    return ok(result)



@app.route("/api/subdomains/enum", methods=["POST"])
@require_token
def subdomains_enum_sync():
    body = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip()
    if not domain:
        return fail("domain مطلوب")
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
    return ok(result)


@app.route("/api/email/recon", methods=["POST"])
@require_token
def email_recon_sync():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip()
    if not email:
        return fail("email مطلوب")
    try:
        return ok(email_recon.recon_email(None, {
            "email": email,
            "check_gravatar": bool(body.get("check_gravatar", True)),
            "check_github": bool(body.get("check_github", True)),
        }))
    except Exception as exc:
        return fail(exc)


@app.errorhandler(404)
def not_found(e):
    return jsonify({"ok": False, "error": "المسار غير موجود"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"ok": False, "error": "خطأ داخلي في السيرفر"}), 500


# ===========================================================================
# Entry Point
# ===========================================================================

def main():
    global API_TOKEN
    parser = argparse.ArgumentParser(
        description="Portable Cybersecurity Toolkit - Web Server")
    parser.add_argument("--host", default="127.0.0.1",
                        help="عنوان الاستماع (افتراضي 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="المنفذ")
    parser.add_argument("--token", default=os.getenv("PCT_TOKEN", ""),
                        help="توكن حماية الـ API (اختياري)")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    API_TOKEN = args.token or None

    print("=" * 62)
    print("  PCT - Portable Cybersecurity Toolkit  |  Web Server v2.0")
    print("=" * 62)
    print(f"  الواجهة   : http://{args.host}:{args.port}/")
    print(f"  الـ API    : http://{args.host}:{args.port}/api/health")
    print(f"  السجل      : {HISTORY_FILE}")
    print(f"  الحماية    : {'توكن مفعّل' if API_TOKEN else 'بدون توكن'}")
    print("=" * 62)

    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
