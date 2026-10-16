# -*- coding: utf-8 -*-
"""Docker-only sandboxed code runner."""
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

LANGUAGES = {
    "python": {"ext": ".py", "image": "python:3.11-slim", "cmd": ["python", "-u", "/work/code.py"], "label": "Python 3.11"},
    "javascript": {"ext": ".js", "image": "node:20-slim", "cmd": ["node", "/work/code.js"], "label": "Node.js 20"},
    "bash": {"ext": ".sh", "image": "bash:5", "cmd": ["bash", "/work/code.sh"], "label": "Bash 5"},
    "sh": {"ext": ".sh", "image": "alpine:3.19", "cmd": ["sh", "/work/code.sh"], "label": "POSIX shell"},
    "ruby": {"ext": ".rb", "image": "ruby:3.3-slim", "cmd": ["ruby", "/work/code.rb"], "label": "Ruby 3.3"},
}
DEFAULT_TIMEOUT = 15
MAX_TIMEOUT = 120
DEFAULT_MAX_OUTPUT = 64 * 1024
MAX_CODE_SIZE = 256 * 1024
DOCKER_PULL_TIMEOUT = 120


def docker_available():
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=5).returncode == 0
    except Exception:
        return False


def image_present(image):
    try:
        return subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True, timeout=10).returncode == 0
    except Exception:
        return False


def pull_image(image):
    try:
        proc = subprocess.run(["docker", "pull", image], capture_output=True, text=True, timeout=DOCKER_PULL_TIMEOUT)
        return proc.returncode == 0, (proc.stderr or "")[:400]
    except subprocess.TimeoutExpired:
        return False, f"pull timeout after {DOCKER_PULL_TIMEOUT}s"
    except Exception as exc:
        return False, str(exc)


def available_languages():
    available = docker_available()
    return {key: {"available": available, "docker": available, "image": cfg["image"], "present": available and image_present(cfg["image"]), "label": cfg["label"]} for key, cfg in LANGUAGES.items()}


def _run_docker(language, code, timeout, max_output):
    cfg = LANGUAGES[language]
    image = cfg["image"]
    filename = f"code{cfg['ext']}"
    work_file = f"/work/{filename}"
    interpreter = " ".join(cfg["cmd"]).replace(f"/work/code{cfg['ext']}", work_file)

    if not image_present(image):
        ok, error = pull_image(image)
        if not ok:
            return {"ok": False, "mode": "docker", "error": f"فشل تنزيل الصورة {image}: {error}"}

    wrapper = f"cat > {work_file} && exec {interpreter}"
    command = [
        "docker", "run", "--rm", "-i",
        "--network=none",
        "--memory=256m", "--memory-swap=256m",
        "--cpus=1.0",
        "--pids-limit=64",
        "--read-only",
        "--tmpfs", "/work:size=16m,mode=1777",
        "--tmpfs", "/tmp:size=32m,mode=1777",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "-e", "PYTHONIOENCODING=utf-8",
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-e", "NODE_OPTIONS=--max-old-space-size=128",
        "-w", "/work", image, "sh", "-c", wrapper,
    ]
    start = time.time()
    try:
        proc = subprocess.run(command, input=code.encode("utf-8"), capture_output=True, timeout=timeout + 15)
        elapsed = round(time.time() - start, 3)
        stdout_raw = proc.stdout or b""
        stderr_raw = proc.stderr or b""
        stdout = stdout_raw.decode("utf-8", "ignore") if isinstance(stdout_raw, bytes) else str(stdout_raw)
        stderr = stderr_raw.decode("utf-8", "ignore") if isinstance(stderr_raw, bytes) else str(stderr_raw)
        return {"ok": True, "mode": "docker", "image": image, "exit_code": proc.returncode, "stdout": stdout[:max_output], "stderr": stderr[:max_output], "elapsed": elapsed, "truncated": len(stdout) > max_output or len(stderr) > max_output}
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", "ignore") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "ignore") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return {"ok": False, "mode": "docker", "image": image, "error": f"Timeout after {timeout}s", "stdout": stdout[:max_output], "stderr": stderr[:max_output]}
    except Exception as exc:
        return {"ok": False, "mode": "docker", "error": str(exc)}


def run_code(job, params):
    code = params.get("code")
    if not isinstance(code, str) or not code:
        raise ValueError("code مطلوب")
    if len(code) > MAX_CODE_SIZE:
        raise ValueError(f"الكود يتجاوز الحد ({MAX_CODE_SIZE})")
    language = (params.get("language") or "python").lower()
    if language not in LANGUAGES:
        raise ValueError(f"لغة غير مدعومة: {language}")
    if not docker_available():
        raise RuntimeError("Docker غير متوفر — code runner يتطلب Docker فقط")
    try: timeout = max(1, min(int(params.get("timeout", DEFAULT_TIMEOUT)), MAX_TIMEOUT))
    except (TypeError, ValueError): timeout = DEFAULT_TIMEOUT
    try: max_output = max(1024, min(int(params.get("max_output", DEFAULT_MAX_OUTPUT)), 1024 * 1024))
    except (TypeError, ValueError): max_output = DEFAULT_MAX_OUTPUT
    if params.get("_progress"): params["_progress"].update(20, f"Running {LANGUAGES[language]['image']}")
    result = _run_docker(language, code, timeout, max_output)
    result["language"] = language
    if params.get("_progress"): params["_progress"].update(100)
    return result
