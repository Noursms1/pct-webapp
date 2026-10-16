# -*- coding: utf-8 -*-
"""Email reconnaissance using allowlisted public sources."""
import hashlib
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request

_ALLOWED_HOSTS = {
    "haveibeenpwned.com", "emailrep.io", "www.gravatar.com", "gravatar.com",
    "cloudflare-dns.com", "api.github.com",
}
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _is_allowed_url(url):
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme == "https" and parsed.hostname in _ALLOWED_HOSTS
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
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "PCT-Email-Recon/1.0",
    })
    result = {"source": "github", "available": True, "error": None,
              "commit_count": 0, "usernames": [], "repos": []}
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
    url = f"https://www.gravatar.com/avatar/{digest}?d=404"
    status, _, error = http_get(url, timeout=10)
    return {"source": "gravatar", "exists": status == 200, "status": status, "error": error}


def recon_email(job, params):
    email = (params.get("email") or "").strip().lower()
    if not _EMAIL_RE.match(email):
        raise ValueError("Invalid email")
    result = {"email": email, "parts": {"local": email.split("@", 1)[0], "domain": email.split("@", 1)[1]}, "github": None, "gravatar": None, "domain_security": None, "errors": []}
    if params.get("check_gravatar", True):
        result["gravatar"] = check_gravatar(email)
    if params.get("check_github", True):
        try:
            result["github"] = check_github_email(email)
            if result["github"].get("error"):
                result["errors"].append(f"github: {result['github']['error']}")
        except Exception as exc:
            result["errors"].append(f"github: {exc}")
    return result
