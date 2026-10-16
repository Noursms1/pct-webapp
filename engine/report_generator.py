# -*- coding: utf-8 -*-
"""Unified HTML, Markdown, and JSON report generation from scan history."""
import html
import json
from datetime import datetime, timezone

from .core import HistoryManager

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
_SEV_ALIASES = {"crit": "critical", "med": "medium", "informational": "info"}


def _norm_sev(value):
    value = str(value or "").strip().lower()
    return _SEV_ALIASES.get(value, value if value in SEVERITY_ORDER else "unknown")


def _finding(source, title, severity, target, timestamp, **values):
    return {"source": source, "title": title, "severity": _norm_sev(severity), "cwe": values.get("cwe"), "cvss": values.get("cvss"), "cvss_vector": values.get("cvss_vector"), "target": target, "location": values.get("location", ""), "description": values.get("description", ""), "evidence": values.get("evidence", ""), "fix": values.get("fix", ""), "extra": values.get("extra", {}), "timestamp": timestamp}


def _iter_findings(entry):
    kind, target, details, timestamp = entry.get("type", ""), entry.get("target", ""), entry.get("details") or {}, entry.get("timestamp", "")
    findings = []
    if kind in ("code", "CodeReview"):
        for item in details.get("findings", []):
            findings.append(_finding("Code Reviewer", item.get("title") or item.get("type") or "Code Finding", item.get("severity"), target, timestamp, cwe=item.get("cwe"), cvss=item.get("cvss_score"), cvss_vector=item.get("cvss_vector"), location=f"line {item.get('line')}", description=item.get("desc", ""), evidence=item.get("snippet", ""), fix=item.get("fix", ""), extra={"rule_id": item.get("rule_id") or item.get("id"), "analysis": item.get("analysis", "regex")}))
    elif kind == "deps":
        for file_info in details.get("files", []):
            for vuln in file_info.get("vulnerabilities", []):
                package = vuln.get("package", "unknown")
                findings.append(_finding("Dependency Scanner", f"{vuln.get('id', 'CVE')} in {package} {vuln.get('version', '')}", "medium", target, timestamp, location=file_info.get("file", ""), description=vuln.get("description", "")[:500], evidence=f"{package}=={vuln.get('version', '')}", fix=f"Upgrade {package} to {', '.join(vuln.get('fix_versions') or ['latest'])}", extra={"id": vuln.get("id"), "aliases": vuln.get("aliases", [])}))
    elif kind == "nuclei":
        for item in details.get("findings", []):
            findings.append(_finding("Nuclei", item.get("template_name") or item.get("template_id", "Finding"), item.get("severity"), item.get("host") or target, timestamp, location=item.get("matched_at", ""), description=item.get("description", ""), evidence=(item.get("extracted_results") or [""])[0], fix="راجع قالب Nuclei للإصلاح المقترح", extra={"template_id": item.get("template_id"), "tags": item.get("tags", [])},))
    elif kind == "osint":
        headers = details.get("security_headers") or {}
        for missing in headers.get("missing", []):
            findings.append(_finding("OSINT / Security Headers", f"Missing {missing.get('header')}", "low", target, timestamp, location=target, description=missing.get("why", ""), evidence="Header not returned in HTTP response", fix=f"Add {missing.get('header')} header"))
        for warning in (details.get("ssl") or {}).get("warnings", []):
            findings.append(_finding("OSINT / TLS", "TLS certificate warning", "medium", target, timestamp, cwe="CWE-295", location=target, description=warning, fix="Verify certificate SAN/CN matching"))
    elif kind == "email":
        for breach in (details.get("breaches") or {}).get("items", []):
            findings.append(_finding("Email Recon — HIBP", f"Breach: {breach.get('title') or breach.get('name')}", "medium", target, timestamp, location=breach.get("date", ""), description=f"Data exposed: {', '.join(breach.get('data_classes', []))}", evidence=f"pwn_count={breach.get('pwn_count', 0)}", fix="Change the password on the affected service"))
        for issue in (details.get("domain_security") or {}).get("issues", []):
            findings.append(_finding("Email Recon — Domain", "Email domain security", "medium", target, timestamp, description=issue, fix="Review SPF/DMARC/DKIM"))
    elif kind == "network":
        risky = {23, 135, 139, 445, 1433, 3306, 3389, 5900, 6379, 27017}
        for port in details.get("open_ports", []):
            if port in risky:
                findings.append(_finding("Network Scanner", f"Risky port open: {port}", "medium", target, timestamp, location=f"port {port}", description=f"Port {port} is open", fix=f"Review whether port {port} must be exposed", extra={"port": port}))
    return findings


def _summarize(findings):
    counts = {key: 0 for key in SEVERITY_ORDER}
    for finding in findings: counts[finding["severity"]] += 1
    risk = "critical" if counts["critical"] else "high" if counts["high"] else "medium" if counts["medium"] else "low" if counts["low"] else "none"
    return {"counts": counts, "total": len(findings), "risk": risk}


def to_markdown(metadata, findings, summary):
    lines = [f"# {metadata['title']}", "", f"**Target:** `{metadata['target']}`  ", f"**Date:** {metadata['date']}  ", "", "## Summary", "", "| Severity | Count |", "|---|---:|"]
    lines += [f"| **{severity.capitalize()}** | {summary['counts'][severity]} |" for severity in SEVERITY_ORDER if summary["counts"][severity]]
    lines += [f"| **Total** | **{summary['total']}** |", "", f"**Overall risk:** `{summary['risk'].upper()}`", ""]
    for index, finding in enumerate(findings, 1):
        lines += [f"## Finding #{index}: {finding['title']}", "", f"- **Source:** {finding['source']}", f"- **Severity:** {finding['severity'].upper()}", f"- **Target:** `{finding['target']}`"]
        if finding.get("cwe"): lines.append(f"- **CWE:** {finding['cwe']}")
        if finding.get("cvss"): lines.append(f"- **CVSS:** {finding['cvss']}")
        lines.append("")
        if finding["description"]: lines += ["### Description", "", finding["description"], ""]
        if finding["evidence"]: lines += ["### Evidence", "", "```", str(finding["evidence"])[:1000], "```", ""]
        if finding["fix"]: lines += ["### Remediation", "", finding["fix"], ""]
    return "\n".join(lines)


def to_html(metadata, findings, summary):
    esc = lambda value: html.escape(str(value or ""))
    cards = []
    for index, finding in enumerate(findings, 1):
        cards.append(f'<article><b class="sev-{esc(finding["severity"])}">{esc(finding["severity"].upper())}</b><h2>#{index} {esc(finding["title"])}</h2><p><code>{esc(finding["target"])}</code></p><p>{esc(finding["description"])}</p><pre>{esc(finding["evidence"])}</pre><strong>Remediation</strong><p>{esc(finding["fix"])}</p></article>')
    return f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>{esc(metadata["title"])}</title><style>body{{font-family:Arial;background:#0b1020;color:#e6ecff;max-width:980px;margin:30px auto}}article{{background:#141c33;border:1px solid #233052;border-radius:12px;padding:18px;margin:18px 0}}pre{{background:#080d1a;padding:12px;overflow:auto}}.sev-critical{{color:#fecaca}}.sev-high{{color:#fed7aa}}.sev-medium{{color:#fef3c7}}.sev-low{{color:#bfdbfe}}</style></head><body><h1>{esc(metadata["title"])}</h1><p>Target: <code>{esc(metadata["target"])}</code> · Findings: {summary["total"]} · Risk: {esc(summary["risk"])}</p>{''.join(cards) or '<p>No findings.</p>'}</body></html>'


def to_json(metadata, findings, summary):
    return {"metadata": metadata, "summary": summary, "findings": findings}


def generate_report(job, params):
    history_file = params.get("history_file")
    if not history_file: raise ValueError("history_file مطلوب")
    entries = HistoryManager(history_file).list(limit=10000) or []
    ids = params.get("entry_ids")
    selected = [entry for entry in entries if entry.get("id") in {int(value) for value in ids}] if ids else entries[:int(params.get("last_n", 20))]
    if not selected: raise ValueError("لا توجد فحوصات محددة")
    findings = sorted([finding for entry in selected for finding in _iter_findings(entry)], key=lambda item: SEVERITY_ORDER.get(item["severity"], 9))
    summary = _summarize(findings)
    target = params.get("target") or selected[0].get("target", "?")
    metadata = {"title": params.get("title") or f"PCT Security Report — {target}", "target": target, "date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "tool_version": "2.0", "entries_count": len(selected)}
    fmt = (params.get("format") or "html").lower()
    if fmt in ("markdown", "md"): content, extension, mime = to_markdown(metadata, findings, summary), "md", "text/markdown"
    elif fmt == "json": content, extension, mime = to_json(metadata, findings, summary), "json", "application/json"
    else: content, extension, mime = to_html(metadata, findings, summary), "html", "text/html"
    return {"format": extension, "mime": mime, "metadata": metadata, "summary": summary, "findings": findings, "content": content, "entries_used": [entry.get("id") for entry in selected]}
