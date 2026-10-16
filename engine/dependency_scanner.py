# -*- coding: utf-8 -*-
"""Dependency vulnerability scanning via pip-audit; never installs packages."""
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

SUPPORTED_FILENAMES = {
    "requirements.txt": "requirements",
    "requirements-dev.txt": "requirements",
    "requirements-prod.txt": "requirements",
    "Pipfile": "pipfile",
    "Pipfile.lock": "pipfile-lock",
    "pyproject.toml": "pyproject",
    "poetry.lock": "poetry-lock",
}
PIP_AUDIT_TIMEOUT = 120
MAX_FILE_SIZE = 2 * 1024 * 1024
_REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*([<>=!~].*?)?\s*(?:;\s*.+)?$")


def parse_requirements_txt(content):
    content = str(content or "").replace("\r\n", "\n").replace("\n", "\n").replace("\r", "\n")
    content = content.encode("ascii", errors="ignore").decode("ascii")
    packages = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split(" #", 1)[0].strip()
        if "://" in line or line.startswith(("git+", "hg+", "svn+", "bzr+")):
            continue
        match = _REQ_RE.match(line)
        if match:
            packages.append({"name": match.group(1), "specifier": (match.group(2) or "").strip()})
    return packages


def pip_audit_available():
    return shutil.which("pip-audit") is not None


def _base_audit(error=None):
    return {"tool": "pip-audit", "available": True, "vulnerabilities": [], "packages_scanned": 0, "error": error}


def _parse_pip_audit_output(stdout, stderr, returncode):
    result = _base_audit()
    text = (stdout or "").strip()
    if not text:
        if returncode != 0:
            result["error"] = (stderr or "pip-audit returned no output").strip()
        return result
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result["error"] = f"Invalid JSON from pip-audit: {exc}"
        return result
    deps = data.get("dependencies", []) if isinstance(data, dict) else []
    if not isinstance(deps, list):
        deps = []
    result["packages_scanned"] = len(deps)
    seen = {}
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        name = dep.get("name", "unknown")
        version = dep.get("version", "")
        for vuln in dep.get("vulns", []) or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = vuln.get("id", "")
            if not vuln_id:
                continue
            key = (name, version, vuln_id)
            aliases = list(vuln.get("aliases") or [])
            if key in seen:
                for alias in aliases:
                    if alias not in seen[key]["aliases"]:
                        seen[key]["aliases"].append(alias)
                continue
            description = vuln.get("description") or ""
            if len(description) > 300:
                description = description[:297] + "..."
            seen[key] = {"package": name, "version": version, "id": vuln_id,
                         "aliases": aliases,
                         "fix_versions": list(vuln.get("fix_versions") or []),
                         "description": description}
    result["vulnerabilities"] = sorted(seen.values(), key=lambda item: (item["package"], item["id"]))
    if returncode not in (0, 1):
        result["error"] = (stderr or f"pip-audit exited with {returncode}").strip()
    return result


def run_pip_audit(req_path, timeout=PIP_AUDIT_TIMEOUT):
    if not pip_audit_available():
        result = _base_audit("pip-audit not installed (pip install pip-audit)")
        result["available"] = False
        return result
    try:
        proc = subprocess.run(["pip-audit", "-r", str(req_path), "--format", "json", "--progress-spinner", "off"], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        result = _base_audit(f"pip-audit timed out after {timeout}s")
        return result
    except Exception as exc:
        return _base_audit(f"Failed to run pip-audit: {exc}")
    return _parse_pip_audit_output(proc.stdout, proc.stderr, proc.returncode)


def _read_text_safely(path):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not p.is_file():
        raise ValueError(f"Not a file: {path}")
    if p.stat().st_size > MAX_FILE_SIZE:
        raise ValueError(f"File too large (max {MAX_FILE_SIZE} bytes)")
    return p.read_text(encoding="utf-8", errors="ignore")


def detect_file_type(filename):
    return SUPPORTED_FILENAMES.get(os.path.basename(filename))


def _unsupported(path):
    return {"file": str(path), "type": "unknown", "supported": False, "error": f"Unsupported file: {os.path.basename(path)}", "packages": [], "packages_scanned": 0, "vulnerabilities": [], "tool": None}


def scan_requirements_file(path):
    kind = detect_file_type(path)
    if kind is None:
        return _unsupported(path)
    content = _read_text_safely(path)
    if kind != "requirements":
        return {"file": str(path), "type": kind, "supported": True, "note": f"Parsing for type '{kind}' is minimal; run pip-audit manually for full analysis.", "packages": [], "packages_scanned": 0, "vulnerabilities": [], "tool": None}
    return _format_requirements_result(str(path), parse_requirements_txt(content), run_pip_audit(path))


def _format_requirements_result(filename, packages, audit):
    vulns = audit["vulnerabilities"]
    return {"file": filename, "type": "requirements", "supported": True, "packages": packages, "packages_parsed": len(packages), "packages_scanned": audit["packages_scanned"], "vulnerabilities": vulns, "vulnerabilities_count": len(vulns), "severity_counts": _summarize_severity(vulns), "risk_level": _risk_level(vulns), "tool": audit["tool"], "tool_available": audit["available"], "error": audit["error"]}


def scan_requirements_content(content, filename="inline_requirements.txt"):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    try:
        audit = run_pip_audit(tmp_path)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    return _format_requirements_result(filename, parse_requirements_txt(content), audit)


def _guess_severity(vuln):
    desc = (vuln.get("description") or "").lower()
    for level, words in {"critical": ("remote code execution", "rce", "arbitrary code"), "high": ("sql injection", "ssrf", "authentication bypass", "privilege escalation"), "medium": ("xss", "csrf", "denial of service", "dos", "path traversal")}.items():
        if any(word in desc for word in words):
            return level
    return "medium"


def _summarize_severity(vulns):
    result = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for vuln in vulns:
        result[_guess_severity(vuln)] += 1
    return result


def _risk_level(vulns):
    if not vulns:
        return "none"
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return min((_guess_severity(v) for v in vulns), key=lambda x: order[x])


def scan_dependencies(job, params):
    progress = params.get("_progress")
    results = []
    path = params.get("path")
    if path:
        if progress:
            progress.update(10, f"Scanning {path}")
        try:
            results.append(scan_requirements_file(path))
        except Exception as exc:
            results.append({"file": str(path), "supported": False, "error": str(exc), "vulnerabilities": []})
    files = params.get("files") or []
    for index, item in enumerate(files, 1):
        if progress and progress.is_cancelled():
            break
        name = item.get("name") or f"file_{index}"
        try:
            if detect_file_type(name) != "requirements":
                results.append(_unsupported(name))
            else:
                results.append(scan_requirements_content(item.get("content") or "", name))
        except Exception as exc:
            results.append({"file": name, "supported": False, "error": str(exc), "vulnerabilities": []})
        if progress:
            progress.update(10 + index * 80 / max(1, len(files)), f"Scanning {name}")
    vulns = [v for result in results for v in result.get("vulnerabilities", [])]
    if progress:
        progress.update(100)
    return {"files_scanned": len(results), "packages_total": sum(r.get("packages_scanned", 0) for r in results), "vulnerabilities_total": len(vulns), "severity_counts": _summarize_severity(vulns), "risk_level": _risk_level(vulns), "files": results}
