# -*- coding: utf-8 -*-
"""Multi-file language-pack scanner used by the web API and background jobs."""

from engine import languages
from engine.rule_engine import get_engine


def scan_multi(job, params):
    progress = params.get("_progress")
    files = params.get("files") or []
    if not files:
        raise ValueError("files مطلوبة")

    languages.reload()
    engine = get_engine()
    results, all_findings, by_lang = [], [], {}
    include_engineering = bool(params.get("include_engineering", True))

    for index, item in enumerate(files, 1):
        name = item.get("name") or f"file_{index}"
        result = engine.scan_file(
            name,
            item.get("content") or "",
            language=params.get("language"),
            include_engineering=include_engineering,
            frameworks_filter=params.get("frameworks"),
            branch=params.get("branch"),
        )
        findings = result.get("findings", [])
        language = result.get("language")
        results.append({
            "file": name,
            "language": language,
            "rules_used": result.get("rules_used", 0),
            "findings": findings,
        })
        all_findings.extend(findings)
        if language:
            by_lang[language] = by_lang.get(language, 0) + len(findings)
        if progress:
            progress.update(index * 95 / len(files), f"Scanning {name}")

    severity_stats = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for finding in all_findings:
        severity = finding.get("severity", "info")
        severity_stats[severity] = severity_stats.get(severity, 0) + 1

    if progress:
        progress.update(100, "Complete")

    return {
        "files_scanned": len(files),
        "total_findings": len(all_findings),
        "severity_stats": severity_stats,
        "by_language": by_lang,
        "results": results,
        "findings": all_findings,
        "supported_languages": languages.list_names(),
    }
