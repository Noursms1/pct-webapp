# -*- coding: utf-8 -*-
"""Optional Nuclei binary integration with JSONL parsing."""
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time

NUCLEI_TIMEOUT = 600
DEFAULT_RATE_LIMIT = 50
DEFAULT_TIMEOUT_PER_REQUEST = 10
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
_ALLOWED_PROTOCOLS = ("http://", "https://")


def nuclei_path():
    return shutil.which("nuclei") or shutil.which("nuclei.exe")


def nuclei_available():
    return nuclei_path() is not None


def nuclei_version(timeout=10):
    path = nuclei_path()
    if not path:
        return None
    try:
        proc = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=timeout)
        output = ((proc.stdout or "") + (proc.stderr or "")).strip()
        return output.splitlines()[0][:120] if output else None
    except Exception:
        return None


def _normalize_target(target):
    if not isinstance(target, str) or not target.strip():
        return None
    value = target.strip()
    return value if value.startswith(_ALLOWED_PROTOCOLS) else "https://" + value


def _normalize_targets(targets):
    if isinstance(targets, str):
        targets = [targets]
    result, seen = [], set()
    for target in targets or []:
        normalized = _normalize_target(target)
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def _parse_nuclei_jsonl(output):
    findings, seen = [], set()
    for line in (output or "").splitlines():
        if not line.strip().startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = data.get("info") or {}
        template_id = data.get("template-id") or data.get("templateID") or ""
        matched = data.get("matched-at") or data.get("matched") or ""
        host = data.get("host") or ""
        key = (template_id, matched, host)
        if key in seen:
            continue
        seen.add(key)
        severity = str(info.get("severity") or "unknown").lower()
        if severity not in VALID_SEVERITIES:
            severity = "unknown"
        findings.append({"template_id": template_id, "template_name": info.get("name", ""), "severity": severity, "type": data.get("type", ""), "host": host, "matched_at": matched, "matcher_name": data.get("matcher-name", ""), "extracted_results": list(data.get("extracted-results") or [])[:5], "description": (info.get("description") or "")[:400], "reference": list(info.get("reference") or [])[:5], "tags": list(info.get("tags") or [])[:10], "curl_command": (data.get("curl-command") or "")[:300], "timestamp": data.get("timestamp", "")})
    findings.sort(key=lambda item: SEVERITY_ORDER.get(item["severity"], 9))
    return findings


def _build_cmd(binary, targets_file, severity=None, tags=None, rate_limit=DEFAULT_RATE_LIMIT, timeout_per_request=DEFAULT_TIMEOUT_PER_REQUEST):
    command = [binary, "-list", targets_file, "-jsonl", "-silent", "-no-color", "-rate-limit", str(int(rate_limit)), "-timeout", str(int(timeout_per_request)), "-no-interactsh", "-disable-update-check", "-stats=false", "-stats-interval", "0"]
    if severity:
        command += ["-severity", ",".join([severity] if isinstance(severity, str) else severity)]
    if tags:
        command += ["-tags", ",".join([tags] if isinstance(tags, str) else tags)]
    return command


def run_nuclei(targets, severity=None, tags=None, rate_limit=DEFAULT_RATE_LIMIT, timeout=NUCLEI_TIMEOUT, timeout_per_request=DEFAULT_TIMEOUT_PER_REQUEST, progress=None, stop_event=None):
    result = {"available": nuclei_available(), "version": None, "findings": [], "count": 0, "severity_counts": {}, "targets": [], "errors": [], "elapsed": 0.0, "cancelled": False}
    if not result["available"]:
        result["errors"].append("nuclei binary not found — install from https://github.com/projectdiscovery/nuclei/releases")
        return result
    result["version"] = nuclei_version()
    normalized = _normalize_targets(targets)
    result["targets"] = normalized
    if not normalized:
        result["errors"].append("No valid targets provided")
        return result
    temp_path = None
    started = time.time()
    try:
        fd, temp_path = tempfile.mkstemp(prefix="pct_nuclei_", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(normalized))
        process = subprocess.Popen(_build_cmd(nuclei_path(), temp_path, severity, tags, rate_limit, timeout_per_request), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore")
        stdout, stderr = process.communicate(timeout=timeout)
        if stop_event and stop_event.is_set():
            result["cancelled"] = True
        result["findings"] = _parse_nuclei_jsonl(stdout)
        if stderr and not result["findings"]:
            result["errors"].append(stderr.strip()[:300])
    except subprocess.TimeoutExpired:
        result["errors"].append(f"Timed out after {timeout}s")
        try: process.kill()
        except Exception: pass
    except Exception as exc:
        result["errors"].append(f"Failed to run nuclei: {exc}")
    finally:
        if temp_path:
            try: os.unlink(temp_path)
            except OSError: pass
    result["count"] = len(result["findings"])
    for finding in result["findings"]:
        level = finding["severity"]
        result["severity_counts"][level] = result["severity_counts"].get(level, 0) + 1
    result["elapsed"] = round(time.time() - started, 2)
    if progress: progress.update(100)
    return result


def scan_with_nuclei(job, params):
    return run_nuclei(params.get("targets") or [], severity=params.get("severity"), tags=params.get("tags"), rate_limit=int(params.get("rate_limit", DEFAULT_RATE_LIMIT)), timeout=int(params.get("timeout", NUCLEI_TIMEOUT)), timeout_per_request=int(params.get("timeout_per_request", DEFAULT_TIMEOUT_PER_REQUEST)), progress=params.get("_progress"), stop_event=params.get("_stop_event"))
