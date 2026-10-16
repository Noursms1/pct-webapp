# -*- coding: utf-8 -*-
"""Validation for JSON language specifications."""
import re

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
ALLOWED_CATEGORIES = {"security", "engineering", "performance", "style", "framework", "custom"}

class SpecError(ValueError):
    pass

def validate_rule(rule, framework=None):
    if not isinstance(rule, dict): raise SpecError("rule must be an object")
    for key in ("id", "name", "pattern"):
        if key not in rule: raise SpecError(f"missing required key: {key}")
    severity = str(rule.get("severity", "medium")).lower()
    category = str(rule.get("category") or ("framework" if framework else "security")).lower()
    if severity not in ALLOWED_SEVERITIES: raise SpecError(f"unknown severity: {severity}")
    if category not in ALLOWED_CATEGORIES: raise SpecError(f"unknown category: {category}")
    try: re.compile(str(rule["pattern"]), re.I | re.M)
    except re.error as exc: raise SpecError(f"invalid regex in {rule['id']}: {exc}")
    return {"id": str(rule["id"]), "name": str(rule["name"]), "category": category, "severity": severity, "pattern": str(rule["pattern"]), "desc": str(rule.get("desc", "")), "fix": str(rule.get("fix", "")), "cwe": rule.get("cwe"), "owasp": rule.get("owasp"), "tags": list(rule.get("tags") or []), "framework": framework, "branch": rule.get("branch")}

def validate_spec(data):
    if not isinstance(data, dict): raise SpecError("spec must be an object")
    name = str(data.get("name", "")).lower()
    if not re.match(r"^[a-z][a-z0-9_+-]*$", name): raise SpecError(f"invalid language name: {name}")
    extensions = data.get("extensions")
    if not isinstance(extensions, list) or not extensions: raise SpecError("extensions must be a non-empty list")
    out = {"name": name, "version": str(data.get("version", "?")), "extensions": [str(x).lower() for x in extensions], "description": str(data.get("description", "")), "docs_url": str(data.get("docs_url", "")), "security_rules": [], "engineering_rules": [], "frameworks": [], "branches": [], "best_practices": []}
    for key in ("security_rules", "engineering_rules"):
        if not isinstance(data.get(key, []), list): raise SpecError(f"{key} must be a list")
        for rule in data.get(key) or []:
            item = validate_rule(rule); item["category"] = "engineering" if key == "engineering_rules" else item["category"]; out[key].append(item)
    for framework in data.get("frameworks") or []:
        if not isinstance(framework, dict) or not framework.get("name"): raise SpecError("invalid framework")
        out["frameworks"].append({"name": str(framework["name"]), "version": str(framework.get("version", "?")), "docs_url": str(framework.get("docs_url", "")), "rules": [validate_rule(rule, framework["name"]) for rule in framework.get("rules") or []]})
    for branch in data.get("branches") or []:
        if not isinstance(branch, dict) or not branch.get("name"): raise SpecError("invalid branch")
        out["branches"].append({"name": str(branch["name"]), "description": str(branch.get("description", "")), "focus": list(branch.get("focus") or []), "top_risks": list(branch.get("top_risks") or []), "rule_ids": list(branch.get("rule_ids") or [])})
    for practice in data.get("best_practices") or []:
        if not isinstance(practice, dict) or not practice.get("title"): raise SpecError("invalid best practice")
        out["best_practices"].append({"title": str(practice["title"]), "description": str(practice.get("description", "")), "example_good": str(practice.get("example_good", "")), "example_bad": str(practice.get("example_bad", "")), "references": list(practice.get("references") or [])})
    return out
