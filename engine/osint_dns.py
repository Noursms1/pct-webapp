# -*- coding: utf-8 -*-
"""OSINT / DNS / HTTP Recon engine."""

import re
import socket
import ssl
import time as _time
import urllib.request
import urllib.error

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

SECURITY_HEADERS = {
    "Strict-Transport-Security": "يفرض HTTPS ويمنع هجمات downgrade.",
    "Content-Security-Policy": "يقلّل أثر XSS وحقن المحتوى.",
    "X-Frame-Options": "يمنع Clickjacking عبر iframe.",
    "X-Content-Type-Options": "يمنع MIME sniffing.",
    "Referrer-Policy": "يحدّ من تسريب الرابط المرجعي.",
    "Permissions-Policy": "يقيّد صلاحيات المتصفح.",
}
DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}
DNS_TYPES_REV = {v: k for k, v in DNS_TYPES.items()}
_DNS_SERVER_CACHE = {"value": None}


def _match_san(hostname, san_list):
    if not hostname or not isinstance(hostname, str):
        return False, None
    host = hostname.lower().rstrip(".")
    if not host:
        return False, None
    for san in san_list or []:
        if not isinstance(san, str) or not san:
            continue
        entry = san.lower().rstrip(".")
        if entry == host:
            return True, "exact"
        if entry.startswith("*."):
            suffix = entry[2:]
            if host.endswith("." + suffix):
                prefix = host[:-(len(suffix) + 1)]
                if prefix and "." not in prefix:
                    return True, "wildcard"
    return False, None


def _self_test_match_san():
    tests = [
        ("info.cern.ch", ["info.cern.ch"], True, "exact"),
        ("INFO.CERN.CH.", ["info.cern.ch"], True, "exact"),
        ("info.cern.ch", ["*.cern.ch"], True, "wildcard"),
        ("a.b.cern.ch", ["*.cern.ch"], False, None),
        ("cern.ch", ["*.cern.ch"], False, None),
        ("api.app.cern.ch", ["*.app.cern.ch"], True, "wildcard"),
        ("a.api.app.cern.ch", ["*.app.cern.ch"], False, None),
    ]
    failed = sum(_match_san(h, s) != (m, t) for h, s, m, t in tests)
    return len(tests) - failed, len(tests), failed


def _encode_name(name):
    name = (name or "").strip(".")
    if not name:
        return b"\x00"
    out = b""
    for part in name.split("."):
        encoded = part.encode("idna")
        out += bytes([len(encoded)]) + encoded
    return out + b"\x00"


def _default_dns_server():
    if _DNS_SERVER_CACHE["value"]:
        return _DNS_SERVER_CACHE["value"]
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    _DNS_SERVER_CACHE["value"] = line.split()[1]
                    return _DNS_SERVER_CACHE["value"]
    except Exception:
        pass
    _DNS_SERVER_CACHE["value"] = "8.8.8.8"
    return _DNS_SERVER_CACHE["value"]


def _read_name(data, offset):
    labels, jumped, end = [], False, offset
    for _ in range(32):
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset, jumped = ptr, True
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode(errors="ignore"))
        offset += length + 1
        if not jumped:
            end = offset
    return ".".join(labels), end


def _parse_dns(data, expected_qtype=None):
    records = []
    if len(data) < 12:
        return records
    if int.from_bytes(data[2:4], "big") & 0x000F == 3:
        return [{"error": "NXDOMAIN"}]
    qdcount = int.from_bytes(data[4:6], "big")
    ancount = int.from_bytes(data[6:8], "big")
    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(data, offset)
        offset += 4
    for _ in range(ancount):
        name, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype = int.from_bytes(data[offset:offset + 2], "big")
        rdlength = int.from_bytes(data[offset + 8:offset + 10], "big")
        start = offset + 10
        rdata = data[start:start + rdlength]
        offset = start + rdlength
        if expected_qtype in ("A", "AAAA") and rtype == 5:
            continue
        if rtype == 1 and rdlength == 4:
            value = ".".join(str(b) for b in rdata)
        elif rtype == 28 and rdlength == 16:
            value = ":".join(f"{rdata[i]:02x}{rdata[i + 1]:02x}" for i in range(0, 16, 2))
        elif rtype in (2, 5):
            value, _ = _read_name(data, start)
        elif rtype == 15:
            pref = int.from_bytes(rdata[:2], "big")
            host, _ = _read_name(data, start + 2)
            value = f"{pref} {host}"
        elif rtype == 16:
            value = rdata[1:].decode(errors="ignore") if rdata else ""
        elif rtype == 6:
            value = "SOA record"
        else:
            value = rdata.hex()[:64]
        records.append({"name": name, "type": DNS_TYPES_REV.get(rtype, str(rtype)), "value": value})
    return records


def dns_query_raw(name, qtype, server=None, timeout=5.0):
    server = server or _default_dns_server()
    qtype = qtype.upper()
    header = (0x1234).to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    packet = header + _encode_name(name) + DNS_TYPES.get(qtype, 1).to_bytes(2, "big") + b"\x00\x01"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return _parse_dns(data, expected_qtype=qtype)


def _looks_like_ip(value):
    return isinstance(value, str) and bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value) or (":" in value and re.match(r"^[0-9a-fA-F:]+$", value)))


def _dns_query_with_cname_separation(domain, qtype):
    records = dns_query_raw(domain, qtype)
    if qtype.upper() in ("A", "AAAA"):
        return [r for r in records if r.get("error") or _looks_like_ip(r.get("value"))]
    return records


def dns_query_dnspython(name, qtype, timeout=5.0):
    if not HAS_DNSPYTHON:
        return _dns_query_with_cname_separation(name, qtype)
    qtype = qtype.upper()
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = resolver.lifetime = timeout
        answers = resolver.resolve(name, qtype, raise_on_no_answer=False)
        if answers.rrset is None:
            return []
        records = []
        for rdata in answers:
            if qtype == "CNAME":
                value = str(rdata.target).rstrip(".")
            elif qtype == "MX":
                value = f"{rdata.preference} {str(rdata.exchange).rstrip('.') }"
            elif qtype == "TXT":
                value = "".join(chunk.decode("utf-8", "ignore") for chunk in getattr(rdata, "strings", ()))
            else:
                value = rdata.to_text().rstrip(".") if qtype in ("NS", "SOA") else rdata.to_text()
            records.append({"name": name, "type": qtype, "value": value})
        return records
    except dns.resolver.NXDOMAIN:
        return [{"error": "NXDOMAIN"}]
    except dns.resolver.NoAnswer:
        return []
    except dns.exception.Timeout:
        return [{"error": "timeout"}]
    except Exception as e:
        return [{"error": str(e)}]


def dns_records(domain, types=None, progress=None):
    types = types or ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    out = {}
    for i, t in enumerate(types, 1):
        if progress and progress.is_cancelled():
            break
        t = t.upper()
        try:
            out[t] = dns_query_dnspython(domain, t) if HAS_DNSPYTHON else _dns_query_with_cname_separation(domain, t)
        except Exception as e:
            out[t] = [{"error": str(e)}]
        if progress:
            progress.update(10 + i * 20 / max(1, len(types)), f"DNS {t}")
    return out


def _get(url, timeout=8, headers=None):
    hdrs = {"User-Agent": "PCT-Scanner/2.0"}
    if headers:
        hdrs.update(headers)
    if HAS_REQUESTS:
        return requests.get(url, timeout=timeout, allow_redirects=True, headers=hdrs)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        return e


def fetch_http_headers(url, timeout=8):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        response = _get(url, timeout=timeout)
        status = getattr(response, "status_code", None) or response.getcode()
        return status, dict(response.headers), getattr(response, "url", url), None
    except Exception as e:
        return None, {}, url, str(e)


def audit_security_headers(headers):
    lower = {k.lower(): v for k, v in headers.items()}
    present = [{"header": n, "value": lower[n.lower()], "why": why} for n, why in SECURITY_HEADERS.items() if n.lower() in lower]
    missing = [{"header": n, "why": why} for n, why in SECURITY_HEADERS.items() if n.lower() not in lower]
    score = round(len(present) * 100 / len(SECURITY_HEADERS))
    grade = "A" if score >= 80 else "B" if score >= 60 else "C" if score >= 40 else "D" if score >= 20 else "F"
    return {"present": present, "missing": missing, "score": score, "grade": grade}


def check_ssl(host, port=443, timeout=6):
    result = {"enabled": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock, ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            result.update({"enabled": True, "tls_version": ssock.version(), "cipher": ssock.cipher()[0]})
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            result.update({"subject": subject.get("commonName", ""), "issuer": issuer.get("organizationName", issuer.get("commonName", "")), "not_before": cert.get("notBefore", ""), "not_after": cert.get("notAfter", "")})
            sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
            result["san"] = sans
            result["san_count"] = len(sans)
            matched, how = _match_san(host, sans)
            result["san_match"] = matched
            result["san_match_type"] = how
            if not matched:
                result["warnings"] = [f"اسم المضيف '{host}' غير موجود في SAN ولا يطابقه أي wildcard وفق RFC 6125."]
            result["days_left"] = int((ssl.cert_time_to_seconds(cert["notAfter"]) - _time.time()) // 86400)
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"شهادة غير موثوقة: {e}"
    except Exception as e:
        result["error"] = str(e)
    return result


def fetch_wellknown(url_base, timeout=6):
    out = {}
    for path in ("/robots.txt", "/.well-known/security.txt"):
        try:
            response = _get(url_base.rstrip("/") + path, timeout=timeout)
            code = getattr(response, "status_code", None) or response.getcode()
            body = response.text if hasattr(response, "text") else response.read(4096).decode(errors="ignore")
            out[path] = {"status": code, "preview": body[:1200]}
        except Exception as e:
            out[path] = {"status": None, "error": str(e)}
    return out


def whois_lookup(domain, server="whois.iana.org", port=43, timeout=8):
    try:
        with socket.create_connection((server, port), timeout=timeout) as sock:
            sock.sendall((domain + "\r\n").encode())
            chunks, total = [], 0
            while total < 20000:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                total += len(data)
            return b"".join(chunks).decode(errors="ignore")
    except Exception as e:
        return f"[!] Whois error: {e}"


def normalize_host(target):
    host = re.sub(r"^https?://", "", (target or "").strip())
    return host.split("/")[0].split(":")[0]


def run_osint(job, params):
    progress = params.get("_progress")
    raw = (params.get("target") or "").strip()
    if not raw:
        raise ValueError("هدف غير صالح.")
    host = normalize_host(raw)
    result = {"input": raw, "host": host}
    try:
        result["ip"] = socket.gethostbyname(host)
        result["resolved"] = True
    except Exception as e:
        result["ip"], result["resolved"], result["resolve_error"] = None, False, str(e)
    if progress:
        progress.update(10, "Forward DNS")
    result["reverse_dns"] = None
    if result["ip"]:
        try:
            result["reverse_dns"] = socket.gethostbyaddr(result["ip"])[0]
        except Exception:
            pass
    if progress:
        progress.update(20, "Reverse DNS")
    result["dns"] = dns_records(host, params.get("dns_types"), progress)
    base = raw if raw.startswith(("http://", "https://")) else "http://" + host
    status, headers, final_url, error = fetch_http_headers(base)
    result.update({"http_status": status, "http_error": error, "final_url": final_url, "headers": headers, "header_count": len(headers), "security_headers": audit_security_headers(headers) if headers else None})
    if progress:
        progress.update(70, "HTTP headers")
    if params.get("ssl", True):
        result["ssl"] = check_ssl(host)
    if progress:
        progress.update(80, "SSL")
    if params.get("wellknown"):
        result["wellknown"] = fetch_wellknown(base)
    if params.get("whois"):
        text = whois_lookup(host)
        result["whois_preview"], result["whois_full"] = text[:3000], text
    alerts = []
    if result.get("security_headers") and result["security_headers"]["missing"]:
        sh = result["security_headers"]
        alerts.append(f"مفقود {len(sh['missing'])} ترويسة أمنية (التقييم {sh['grade']}).")
    ssl_info = result.get("ssl") or {}
    if ssl_info.get("days_left") is not None and ssl_info["days_left"] < 15:
        alerts.append(f"شهادة TLS تنتهي بعد {ssl_info['days_left']} يوم.")
    alerts.extend(ssl_info.get("warnings", []))
    if headers.get("Server"):
        alerts.append(f"الخادم يكشف نسخته: {headers['Server']}")
    result["alerts"] = alerts
    if progress:
        progress.update(100, "تم")
    return result


if __name__ == "__main__":
    passed, total, failed = _self_test_match_san()
    print(f"_match_san tests: {passed}/{total} passed, {failed} failed")
    print(f"dnspython available: {HAS_DNSPYTHON}")
    print(f"requests available: {HAS_REQUESTS}")
    raise SystemExit(1 if failed else 0)
