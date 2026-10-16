# -*- coding: utf-8 -*-
"""Unified language-pack rule engine."""
from . import languages
from .code_analyzer import analyze_ast
from .rules_store import RulesStore

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

class UnifiedRuleEngine:
    def __init__(self, rules_store=None):
        self.store = rules_store or RulesStore()

    def scan_file(self, name, content, language=None, include_engineering=True,
                  include_frameworks=True, frameworks_filter=None, branch=None):
        try:
            languages.reload()
        except Exception:
            pass
        lang_name = language or languages.detect(name)
        lang = languages.get(lang_name)
        if not lang:
            return {"language": lang_name, "findings": [], "rules_used": 0}
        rules = list(lang.security_rules)
        if include_engineering:
            rules += lang.engineering_rules
        if include_frameworks:
            for framework in lang.frameworks:
                if not frameworks_filter or framework.name in frameworks_filter:
                    rules += framework.rules
        if branch:
            rules = lang.rules_for_branch(branch)
        findings = []
        for line_number, line in enumerate(content.splitlines(), 1):
            for rule in rules:
                if rule.pattern.search(line):
                    findings.append({"line": line_number, "rule_id": rule.id,
                                     "type": rule.name, "category": rule.category,
                                     "severity": rule.severity, "cwe": rule.cwe,
                                     "snippet": line.strip()[:120], "desc": rule.desc,
                                     "fix": rule.fix, "language": lang_name,
                                     "source": "pack", "file": name})
        if lang_name == "python":
            try:
                for finding in analyze_ast(content):
                    finding.update({"language": "python", "category": "security", "source": "ast", "file": name})
                    findings.append(finding)
            except Exception:
                pass
        unique, seen = [], set()
        for finding in findings:
            key = (finding["line"], finding["rule_id"])
            if key not in seen:
                seen.add(key); unique.append(finding)
        unique.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["line"]))
        return {"language": lang_name, "findings": unique, "rules_used": len(rules)}

_ENGINE = None
def get_engine():
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = UnifiedRuleEngine()
    return _ENGINE

def scan_multi(job, params):
    files = params.get("files") or []
    if not files:
        raise ValueError("files مطلوبة")
    engine = get_engine(); results = []; all_findings = []; by_language = {}
    for item in files:
        name = item.get("name") or "unknown"
        result = engine.scan_file(name, item.get("content") or "", params.get("language"), params.get("include_engineering", True), True, params.get("frameworks"), params.get("branch"))
        findings = result.get("findings", []); language = result.get("language")
        results.append({"file": name, "language": language, "rules_used": result.get("rules_used", 0), "findings": findings})
        all_findings.extend(findings)
        if language:
            by_language[language] = by_language.get(language, 0) + len(findings)
    severity_stats = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for finding in all_findings:
        severity_stats[finding["severity"]] = severity_stats.get(finding["severity"], 0) + 1
    return {"files_scanned": len(files), "total_findings": len(all_findings), "severity_stats": severity_stats, "by_language": by_language, "results": results, "findings": all_findings, "languages_meta": languages.all_metadata()}
