# -*- coding: utf-8 -*-
"""
=============================================================================
 Engine Module: Network Scanner
-----------------------------------------------------------------------------
 فحص المنافذ (Fast / Full / Custom) بمعالجة متعددة الخيوط + Banner Grabbing
=============================================================================
"""

import socket
import threading
import time

# منافذ شائعة مع وصف مختصر
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443,
                445, 993, 995, 1723, 3306, 3389, 5900, 8080]

PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 27017: "mongodb", 8080: "http-proxy", 8443: "https-alt",
}

# منافذ عالية الخطورة إذا كانت مفتوحة للإنترنت
RISKY_PORTS = {23, 135, 139, 445, 1433, 3306, 3389, 5900, 6379, 27017}


def resolve(target):
    """حل الاسم إلى IP مع إرجاع كل العناوين إن وُجدت."""
    ips = []
    try:
        infos = socket.getaddrinfo(target, None)
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception as e:
        raise ValueError(f"فشل حل العنوان '{target}': {e}")
    return ips


def scan_one_port(host, port, timeout, collector, lock, stop_event):
    """فحص منفذ واحد."""
    if stop_event.is_set():
        return
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((host, port)) == 0:
            with lock:
                collector.append(port)
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass


def grab_banner(host, port, timeout=2.0):
    """محاولة جلب Banner الخدمة."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if port in (80, 8080, 8000, 8888):
            s.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        elif port == 443:
            # لا نُجري handshake TLS، فقط ننتظر رد الخدمة
            pass
        data = s.recv(1024)
        s.close()
        if not data:
            return ""
        text = data.decode(errors="ignore").strip()
        return text.splitlines()[0][:160]
    except Exception:
        return ""


def scan_ports(host, ports, timeout=1.0, max_threads=200, progress=None,
               stop_event=None):
    """فحص قائمة منافذ بخيوط متوازية مع تتبع تقدم."""
    open_ports = []
    lock = threading.Lock()
    stop_event = stop_event or threading.Event()
    total = len(ports)
    done = [0]
    counter_lock = threading.Lock()
    threads = []

    def worker(port):
        scan_one_port(host, port, timeout, open_ports, lock, stop_event)
        with counter_lock:
            done[0] += 1
            if progress and (done[0] % max(1, total // 100) == 0 or done[0] == total):
                progress.update(done[0] * 100.0 / total,
                                f"{done[0]}/{total} منفذ")

    start = time.time()
    for port in ports:
        if stop_event.is_set():
            break
        t = threading.Thread(target=worker, args=(port,), daemon=True)
        t.start()
        threads.append(t)
        while threading.active_count() > max_threads:
            time.sleep(0.001)
            if stop_event.is_set():
                break

    for t in threads:
        t.join()

    return sorted(open_ports), round(time.time() - start, 2)


def service_name(port):
    if port in PORT_SERVICES:
        return PORT_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except Exception:
        return "unknown"


def scan_network(job, params):
    """
    نقطة دخول المحرك: فحص شبكة.

    params:
      target  : str   -> hostname / IP
      mode    : str   -> fast | full | custom
      ports   : list  -> عند mode=custom
      timeout : float -> مهلة الاتصال
      banner  : bool  -> جلب Banner
      threads : int   -> أقصى عدد خيوط
    """
    progress = params.get("_progress")
    stop_event = params.get("_stop_event")
    target = (params.get("target") or "").strip()
    if not target:
        raise ValueError("هدف غير صالح.")

    mode = params.get("mode", "fast")
    timeout = float(params.get("timeout", 1.0))
    do_banner = bool(params.get("banner", False))
    max_threads = int(params.get("threads", 200))

    if mode == "full":
        ports = list(range(1, 65536))
        timeout = min(timeout, 0.6)
    elif mode == "custom":
        ports = sorted({int(p) for p in (params.get("ports") or []) if 0 < int(p) < 65536})
        if not ports:
            raise ValueError("لم تُحدَّد منافذ صالحة.")
    else:
        mode = "fast"
        ports = list(COMMON_PORTS)

    ips = resolve(target)
    primary_ip = ips[0]
    if progress:
        progress.update(2, f"تم حل {target} -> {primary_ip}")

    open_ports, elapsed = scan_ports(
        primary_ip, ports, timeout=timeout, max_threads=max_threads,
        progress=progress, stop_event=stop_event,
    )

    results = []
    for i, p in enumerate(open_ports, 1):
        if stop_event and stop_event.is_set():
            break
        item = {
            "port": p,
            "service": service_name(p),
            "risky": p in RISKY_PORTS,
            "banner": "",
        }
        if do_banner:
            item["banner"] = grab_banner(primary_ip, p)
        results.append(item)
        if progress and do_banner:
            progress.update(90 + i * 10.0 / max(1, len(open_ports)),
                            f"Banner على {p}")

    if progress:
        progress.update(100)

    return {
        "target": target,
        "ip": primary_ip,
        "all_ips": ips,
        "mode": mode,
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "risky_ports": [p for p in open_ports if p in RISKY_PORTS],
        "services": results,
        "elapsed": elapsed,
        "timeout": timeout,
        "cancelled": bool(stop_event and stop_event.is_set()),
    }
