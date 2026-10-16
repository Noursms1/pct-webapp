# -*- coding: utf-8 -*-
"""PCT - Production Server Runner (Windows-friendly)"""

import os
import sys
import argparse
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()
PID_FILE = BASE_DIR / "server.pid"
LOG_FILE = BASE_DIR / "server.log"
HOST_DEFAULT = "127.0.0.1"
PORT_DEFAULT = 8000


def is_running():
    if not PID_FILE.exists():
        return None
    try:
        pid = int(PID_FILE.read_text().strip())
    except Exception:
        return None
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", f"PID eq {pid}"],
            stderr=subprocess.DEVNULL, text=True
        )
        if str(pid) in out:
            return pid
    except Exception:
        pass
    return None


def stop_server():
    pid = is_running()
    if not pid:
        print("[!] Server is not running.")
        if PID_FILE.exists():
            PID_FILE.unlink()
        return
    print(f"[*] Stopping server (PID={pid})...")
    subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if PID_FILE.exists():
        PID_FILE.unlink()
    print("[+] Stopped.")


def status():
    pid = is_running()
    if pid:
        print(f"[+] Server is running (PID={pid})")
    else:
        print("[*] Server is not running.")


def start_server(host, port, token):
    if is_running():
        print("[!] Server is already running. Use --stop first.")
        return 1

    sys.path.insert(0, str(BASE_DIR))
    os.chdir(BASE_DIR)

    if token:
        os.environ["PCT_TOKEN"] = token

    try:
        from server import app
    except Exception as e:
        print(f"[!] Failed to import server.py: {e}")
        return 1

    from waitress import serve

    PID_FILE.write_text(str(os.getpid()))

    print("=" * 62)
    print("  PCT - Portable Cybersecurity Toolkit  |  Production Server")
    print("=" * 62)
    print(f"  URL     : http://{host}:{port}/")
    print(f"  PID     : {os.getpid()}")
    print(f"  Log     : {LOG_FILE}")
    print(f"  Auth    : {'token enabled' if token else 'no token'}")
    print("=" * 62)
    print("  To stop: python run_server.py --stop")
    print("=" * 62)

    try:
        serve(app, host=host, port=port, threads=8)
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
    finally:
        if PID_FILE.exists():
            PID_FILE.unlink()
    return 0


def main():
    parser = argparse.ArgumentParser(description="PCT Production Runner")
    parser.add_argument("--host", default=HOST_DEFAULT)
    parser.add_argument("--port", type=int, default=PORT_DEFAULT)
    parser.add_argument("--token", default=os.getenv("PCT_TOKEN", ""))
    parser.add_argument("--stop", action="store_true")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()

    if args.stop:
        stop_server()
        return
    if args.status:
        status()
        return
    sys.exit(start_server(args.host, args.port, args.token or None))


if __name__ == "__main__":
    main()