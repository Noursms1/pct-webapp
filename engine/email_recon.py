# -*- coding: utf-8 -*-
"""Email reconnaissance using allowlisted public sources."""
import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

_ALLOWED_HOSTS = {
    "haveibeenpwned.com", "emailrep.io", "www.gravatar.com", "gravatar.com",
    "cloudflare-dns.com", "api.github.com",
}
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_HIBP_MIN_INTERVAL = 1.5
_hibp_lock = threading.Lock()
_hibp_last = [0.0]
DOH_URL = "https://cloudflare-dns.com/dns-query"
DOH_TIMEOUT = 10
DKIM_SELECTORS = ("google", "default", "selector1", "selector2", "k1")


def _is_allowed_url(url):
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme == "https" and (parsed.hostname or "").lower() in _ALLOWED_HOSTS
    except Exception:
        return False


def http_get(url, timeout=10, headers=None):
    if not _is_allowed_url(url):
        return None, "", "blocked URL"
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.getcode(), response.read().decode("utf-8", errors="ignore"), None
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="ignore"), f"HTTP {exc.code}"
    except Exception as exc:
        return None, "", f"{type(exc).__name__}: {exc}"


def check_github_email(email, timeout=10, max_results=5):
    query = urllib.parse.quote(f"author-email:{email}")
    url = f"https://api.github.com/search/commits?q={query}&per_page={max_results}"
    status, body, error = http_get(url, timeout=timeout, headers={
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "PCT-Email-Recon/1.0",
    })
    result = {"source": "github", "available": True, "error": None, "commit_count": 0, "usernames": [], "repos": []}
    if status == 403:
        result.update(available=False, error="GitHub rate limit reached (10/min unauthenticated)")
        return result
    if status == 422:
        return result
    if error or status != 200:
        result["error"] = error or f"HTTP {status}"
        return result
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        result["error"] = f"invalid JSON: {exc}"
        return result
    result["commit_count"] = int(data.get("total_count", 0))
    result["usernames"] = sorted({(item.get("author") or {}).get("login") for item in data.get("items", []) if (item.get("author") or {}).get("login")})
    result["repos"] = sorted({(item.get("repository") or {}).get("full_name") for item in data.get("items", []) if (item.get("repository") or {}).get("full_name")})[:10]
    return result


def check_gravatar(email):
    digest = hashlib.md5(email.strip().lower().encode()).hexdigest()
    status, _, error = http_get(f"https://www.gravatar.com/avatar/{digest}?d=404", timeout=10)
    return {"source": "gravatar", "exists": status == 200, "status": status, "error": error}


def check_emailrep(email, timeout=10):
    status, body, error = http_get(f"https://emailrep.io/{urllib.parse.quote(email)}", timeout=timeout, headers={"Accept": "application/json"})
    result = {"source": "emailrep", "available": True, "error": None, "data": None}
    if status == 429:
        result.update(available=False, error="EmailRep rate limit (10/day anon)")
        return result
    if error or status != 200:
        result["error"] = error or f"HTTP {status}"
        return result
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        result["error"] = f"invalid JSON: {exc}"
        return result
    details = data.get("details") or {}
    result["data"] = {
        "reputation": data.get("reputation"), "suspicious": bool(data.get("suspicious", False)),
        "references": int(data.get("references", 0) or 0), "blacklisted": bool(details.get("blacklisted", False)),
        "malicious_activity": bool(details.get("malicious_activity", False)), "credentials_leaked": bool(details.get("credentials_leaked", False)),
        "data_breach": bool(details.get("data_breach", False)), "domain_exists": bool(details.get("domain_exists", False)),
        "profiles": list(details.get("profiles") or []),
    }
    return result


def _doh_query(name, rtype, timeout=DOH_TIMEOUT):
    query = urllib.parse.urlencode({"name": name, "type": rtype})
    status, body, error = http_get(f"{DOH_URL}?{query}", timeout=timeout, headers={"Accept": "application/dns-json"})
    if error or status != 200:
        return None
    try:
        return json.loads(body).get("Answer") or []
    except (json.JSONDecodeError, AttributeError):
        return None


def check_email_domain_security(domain, timeout=DOH_TIMEOUT):
    result = {"domain": domain, "mx": [], "spf": None, "dmarc": None, "dkim_selectors": {}, "mta_sts": None, "bimi": None, "issues": [], "risk": "unknown"}
    for answer in _doh_query(domain, "MX", timeout) or []:
        if answer.get("type") == 15:
            parts = (answer.get("data") or "").split()
            if len(parts) >= 2:
                try: result["mx"].append({"priority": int(parts[0]), "host": parts[1].rstrip(".")})
                except ValueError: pass
    if not result["mx"]: result["issues"].append("MX مفقود — النطاق قد لا يستقبل بريدًا")
    for answer in _doh_query(domain, "TXT", timeout) or []:
        value = (answer.get("data") or "").strip('"')
        if answer.get("type") == 16 and value.lower().startswith("v=spf1"):
            result["spf"] = value; break
    if not result["spf"]: result["issues"].append("SPF مفقود — عرضة لانتحال البريد")
    for answer in _doh_query(f"_dmarc.{domain}", "TXT", timeout) or []:
        value = (answer.get("data") or "").strip('"')
        if answer.get("type") == 16 and value.lower().startswith("v=dmarc1"):
            result["dmarc"] = value; break
    if not result["dmarc"]: result["issues"].append("DMARC مفقود — لا حماية من انتحال البريد")
    elif "p=none" in result["dmarc"].lower(): result["issues"].append("DMARC policy = none (monitor only)")
    for selector in DKIM_SELECTORS:
        for answer in _doh_query(f"{selector}._domainkey.{domain}", "TXT", timeout) or []:
            value = (answer.get("data") or "").strip('"')
            if answer.get("type") == 16 and ("v=dkim1" in value.lower() or "p=" in value):
                result["dkim_selectors"][selector] = value[:200]; break
    if not result["dkim_selectors"]: result["issues"].append("DKIM: لم يُعثر على selectors شائعة")
    for key, query in (("mta_sts", f"_mta-sts.{domain}"), ("bimi", f"default._bimi.{domain}")):
        for answer in _doh_query(query, "TXT", timeout) or []:
            if answer.get("type") == 16:
                result[key] = (answer.get("data") or "").strip('"'); break
    dmarc = (result["dmarc"] or "").lower()
    result["risk"] = "high" if not result["spf"] and not result["dmarc"] else "medium" if not result["dmarc"] or "p=none" in dmarc else "low"
    return result


def check_breaches(email, timeout=10):
    api_key = (os.environ.get("HIBP_API_KEY") or "").strip()
    result = {"source": "hibp", "available": bool(api_key), "error": None, "breaches": [], "count": 0}
    if not api_key:
        result["error"] = "HIBP_API_KEY not set (get one at haveibeenpwned.com/API/Key)"
        return result
    with _hibp_lock:
        wait = _HIBP_MIN_INTERVAL - (time.time() - _hibp_last[0])
        if wait > 0: time.sleep(wait)
        _hibp_last[0] = time.time()
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false"
    status, body, error = http_get(url, timeout=timeout, headers={"hibp-api-key": api_key, "Accept": "application/json"})
    if status == 404: return result
    if status == 401: result["error"] = "HIBP: invalid API key"; return result
    if status == 429: result["error"] = "HIBP rate limit — retry later"; return result
    if error or status != 200: result["error"] = error or f"HTTP {status}"; return result
    try: data = json.loads(body)
    except json.JSONDecodeError as exc: result["error"] = f"invalid JSON: {exc}"; return result
    for breach in data if isinstance(data, list) else []:
        result["breaches"].append({"name": breach.get("Name", ""), "title": breach.get("Title", ""), "domain": breach.get("Domain", ""), "date": breach.get("BreachDate", ""), "pwn_count": breach.get("PwnCount", 0), "data_classes": list(breach.get("DataClasses") or []), "is_verified": bool(breach.get("IsVerified", False)), "is_sensitive": bool(breach.get("IsSensitive", False))})
    result["breaches"].sort(key=lambda item: item.get("date") or "", reverse=True)
    result["count"] = len(result["breaches"])
    return result


def recon_email(job, params):
    email = (params.get("email") or "").strip().lower()
    if not _EMAIL_RE.match(email): raise ValueError("Invalid email")
    local, domain = email.split("@", 1)
    result = {"email": email, "email_hash": hashlib.sha256(email.encode()).hexdigest()[:16], "parts": {"local": local, "domain": domain}, "breaches": {"count": 0, "items": [], "available": False, "error": None}, "reputation": None, "gravatar": None, "github": None, "domain_security": None, "errors": []}
    if params.get("check_gravatar", True): result["gravatar"] = check_gravatar(email)
    if params.get("check_github", True):
        try:
            result["github"] = check_github_email(email)
            if result["github"].get("error"): result["errors"].append(f"github: {result['github']['error']}")
        except Exception as exc: result["errors"].append(f"github: {exc}")
    if params.get("check_breach", True):
        try:
            breach = check_breaches(email)
            result["breaches"] = {"count": breach["count"], "items": breach["breaches"], "available": breach["available"], "error": breach["error"]}
            if breach["error"] and breach["available"]: result["errors"].append(f"hibp: {breach['error']}")
        except Exception as exc: result["errors"].append(f"hibp: {exc}")
    if params.get("check_rep", True):
        try:
            rep = check_emailrep(email); result["reputation"] = rep.get("data")
            if rep.get("error"): result["errors"].append(f"emailrep: {rep['error']}")
        except Exception as exc: result["errors"].append(f"emailrep: {exc}")
    if params.get("check_domain", True):
        try: result["domain_security"] = check_email_domain_security(domain)
        except Exception as exc: result["errors"].append(f"domain: {exc}")
    return result
