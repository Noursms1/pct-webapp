# -*- coding: utf-8 -*-
"""Passive subdomain enumeration with SSRF-safe optional probing."""
import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_TIMEOUT = 15
DEFAULT_PROBE_TIMEOUT = 5
DEFAULT_PROBE_WORKERS = 20
USER_AGENT = "PCT-Subdomain-Enum/1.0"
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_BLOCKED_HOSTS = {"localhost", "localhost.localdomain", "127.0.0.1", "0.0.0.0", "::1"}


def is_valid_domain(domain):
    if not domain or not isinstance(domain, str):
        return False
    value = domain.strip().lower().rstrip(".")
    return value not in _BLOCKED_HOSTS and ".." not in value and bool(_DOMAIN_RE.match(value))


def is_valid_subdomain(sub, root):
    if not isinstance(sub, str) or not isinstance(root, str):
        return False
    sub = sub.strip().lower().rstrip(".")
    root = root.strip().lower().rstrip(".")
    if not sub or not root or (sub != root and not sub.endswith("." + root)):
        return False
    if sub == root:
        return True
    prefix = sub[:-(len(root) + 1)]
    return bool(prefix) and all(_LABEL_RE.match(label) for label in prefix.split("."))


def normalize_subdomain(sub):
    if not isinstance(sub, str) or not sub.strip():
        return None
    value = sub.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    if not value or ".." in value or " " in value:
        return None
    return value


def _is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified


def _is_safe_url(url):
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower().strip()
    if not host or host in _BLOCKED_HOSTS:
        return False
    try:
        return not _is_private_ip(host)
    except Exception:
        return False
    # Resolve hostnames and reject every private address to prevent DNS rebinding targets.
    try:
        return all(not _is_private_ip(info[4][0]) for info in socket.getaddrinfo(host, None))
    except Exception:
        return False


def http_get(url, timeout=DEFAULT_TIMEOUT):
    if not _is_safe_url(url):
        return None, "", "blocked URL (SSRF guard)"
    try:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.getcode(), response.read().decode("utf-8", errors="ignore"), None
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return exc.code, body, f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return None, "", f"URLError: {exc.reason}"
    except Exception as exc:
        return None, "", f"{type(exc).__name__}: {exc}"


def _source_result(source, status, error=None, raw=None):
    return {"source": source, "status": status, "error": error, "raw": sorted(raw or [])}


def query_crt_sh(domain, timeout=DEFAULT_TIMEOUT):
    status, body, error = http_get(f"https://crt.sh/?q={urllib.parse.quote('%.', safe='')}{urllib.parse.quote(domain)}&output=json", timeout)
    if error or status != 200:
        return _source_result("crt.sh", status, error or f"HTTP {status}")
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        return _source_result("crt.sh", status, f"invalid JSON: {exc}")
    names = set()
    for entry in data if isinstance(data, list) else []:
        if isinstance(entry, dict):
            for value in (entry.get("name_value", ""), entry.get("common_name", "")):
                for line in str(value or "").splitlines():
                    normalized = normalize_subdomain(line)
                    if normalized:
                        names.add(normalized)
    return _source_result("crt.sh", status, raw=names)


def query_hackertarget(domain, timeout=DEFAULT_TIMEOUT):
    url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
    status, body, error = http_get(url, timeout)
    if error or status != 200:
        return _source_result("hackertarget", status, error or f"HTTP {status}")
    if body.strip().lower().startswith(("error", "api count", "no records")):
        return _source_result("hackertarget", status, body.strip()[:120])
    names = {normalize_subdomain(line.split(",", 1)[0]) for line in body.splitlines() if line.strip()}
    return _source_result("hackertarget", status, raw={name for name in names if name})


def query_alienvault(domain, timeout=DEFAULT_TIMEOUT):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}/passive_dns"
    status, body, error = http_get(url, timeout)
    if error or status != 200:
        return _source_result("alienvault", status, error or f"HTTP {status}")
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        return _source_result("alienvault", status, f"invalid JSON: {exc}")
    names = {normalize_subdomain(item.get("hostname")) for item in data.get("passive_dns", []) if isinstance(item, dict)}
    return _source_result("alienvault", status, raw={name for name in names if name})


SOURCES = {"crt.sh": query_crt_sh, "hackertarget": query_hackertarget, "alienvault": query_alienvault}


def aggregate_sources(domain, sources=None, timeout=DEFAULT_TIMEOUT, progress=None):
    selected = sources or list(SOURCES)
    per_source, merged = {}, set()
    for index, source in enumerate(selected, 1):
        if source not in SOURCES:
            continue
        if progress:
            progress.update(5 + index * 25 / max(1, len(selected)), f"Querying {source}")
        try:
            result = SOURCES[source](domain, timeout=timeout)
        except Exception as exc:
            result = _source_result(source, None, f"{type(exc).__name__}: {exc}")
        per_source[source] = result
        merged.update(result.get("raw", []))
    valid = sorted(item for item in merged if is_valid_subdomain(item, domain))
    return {"domain": domain, "subdomains": valid, "count": len(valid), "sources": per_source}


def detect_wildcards(domain, subdomains):
    root_count = len(domain.split("."))
    return [sub for sub in subdomains if any(len(label) <= 1 for label in sub.split(".")[:-root_count]) and len(sub.split(".")) - root_count >= 3]


def probe_one(host, timeout=DEFAULT_PROBE_TIMEOUT):
    result = {"host": host, "http_status": None, "https_status": None, "server": "", "title": "", "error": None}
    blocked = True
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        if not _is_safe_url(url):
            continue
        blocked = False
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read(4096).decode("utf-8", errors="ignore")
                code = response.getcode()
                if scheme == "https": result["https_status"] = code
                else: result["http_status"] = code
                result["server"] = dict(response.headers).get("Server", "")[:80]
                match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                result["title"] = match.group(1).strip()[:120] if match else ""
        except Exception:
            pass
    if blocked:
        result["error"] = "blocked"
    return result


def probe_all(subdomains, timeout=DEFAULT_PROBE_TIMEOUT, workers=DEFAULT_PROBE_WORKERS, progress=None, stop_event=None):
    if not subdomains:
        return []
    results, total = [], len(subdomains)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(probe_one, host, timeout): host for host in subdomains}
        for index, future in enumerate(as_completed(futures), 1):
            if stop_event and stop_event.is_set():
                break
            try:
                results.append(future.result())
            except Exception as exc:
                results.append({"host": futures[future], "error": str(exc)})
            if progress and index % 5 == 0:
                progress.update(70 + index * 25 / total, f"Probed {index}/{total}")
    return results


def enumerate_subdomains(job, params):
    progress = params.get("_progress")
    domain = (params.get("domain") or "").strip().lower().rstrip(".")
    if not is_valid_domain(domain):
        raise ValueError(f"Invalid domain: {domain!r}")
    timeout = int(params.get("timeout", DEFAULT_TIMEOUT))
    probe_timeout = int(params.get("probe_timeout", DEFAULT_PROBE_TIMEOUT))
    probe_http = bool(params.get("probe_http", False))
    aggregate = aggregate_sources(domain, params.get("sources"), timeout, progress)
    probes = probe_all(aggregate["subdomains"], probe_timeout, progress=progress, stop_event=params.get("_stop_event")) if probe_http else []
    if progress:
        progress.update(100)
    return {"domain": domain, "subdomains": aggregate["subdomains"], "count": aggregate["count"], "wildcards": detect_wildcards(domain, aggregate["subdomains"]), "sources": {key: {"status": value.get("status"), "error": value.get("error"), "found": len(value.get("raw", []))} for key, value in aggregate["sources"].items()}, "probes": probes, "probe_enabled": probe_http}
