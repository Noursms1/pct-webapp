# -*- coding: utf-8 -*-
"""PCT - Production Server Runner (Windows-friendly)"""

import os
import sys
import argparse
import atexit
import socket
import subprocess
import time
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()
PID_FILE = BASE_DIR / "server.pid"
LOG_FILE = BASE_DIR / "server.log"
HOST_DEFAULT = "127.0.0.1"
PORT_DEFAULT = 8000


REA_SIDECAR_PORT = int(os.getenv("REA_BRIDGE_PORT", "7801"))
_rea_proc = None


def wait_for_port(port, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def start_rea_sidecar():
    global _rea_proc
    sidecar_dir = BASE_DIR / "sidecar"
    package_file = sidecar_dir / "package.json"
    if not package_file.exists():
        raise RuntimeError("sidecar/package.json is missing")

    npm = "npm.cmd" if os.name == "nt" else "npm"
    node_modules = sidecar_dir / "node_modules"
    if not node_modules.exists():
        print("[*] Installing REA sidecar dependencies...")
        subprocess.run([npm, "install"], cwd=sidecar_dir, check=True)

    env = {**os.environ, "REA_BRIDGE_PORT": str(REA_SIDECAR_PORT)}
    _rea_proc = subprocess.Popen([npm, "run", "start"], cwd=sidecar_dir, env=env)
    if not wait_for_port(REA_SIDECAR_PORT):
        stop_rea_sidecar()
        raise RuntimeError(f"REA sidecar did not start on port {REA_SIDECAR_PORT}")
    print(f"[+] REA sidecar ready on http://127.0.0.1:{REA_SIDECAR_PORT}")


def stop_rea_sidecar():
    global _rea_proc
    if _rea_proc is None:
        return
    if _rea_proc.poll() is None:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(_rea_proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            _rea_proc.terminate()
            try:
                _rea_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _rea_proc.kill()
    _rea_proc = None


atexit.register(stop_rea_sidecar)


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


def start_server(host, port, token, with_rea=True):
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

    if with_rea:
        try:
            start_rea_sidecar()
        except Exception as e:
            print(f"[!] Failed to start REA sidecar: {e}")
            return 1

    from waitress import serve

    PID_FILE.write_text(str(os.getpid()))

    print("=" * 62)
    print("  PCT - Portable Cybersecurity Toolkit  |  Production Server")
    print("=" * 62)
    print(f"  URL     : http://{host}:{port}/")
    print(f"  PID     : {os.getpid()}")
    print(f"  Log     : {LOG_FILE}")
    print(f"  REA     : {'enabled on :' + str(REA_SIDECAR_PORT) if with_rea else 'disabled'}")
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
    parser.add_argument("--no-rea", action="store_true", help="Do not start the REA sidecar")
    args = parser.parse_args()

    if args.stop:
        stop_server()
        return
    if args.status:
        status()
        return
    sys.exit(start_server(args.host, args.port, args.token or None, with_rea=not args.no_rea))


if __name__ == "__main__":
    main()