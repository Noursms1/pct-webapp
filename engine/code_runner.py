# -*- coding: utf-8 -*-
"""Docker-only multi-file code runner with SAST and syntax checks."""
import ast
import io
import os
import shutil
import subprocess
import tarfile
import time

LANGUAGES = {
    "python": {"ext": ".py", "entry_default": "main.py", "image": "python:3.11-slim", "run": ["python", "-u", "/work/{main}"], "label": "Python 3.11 (slim)"},
    "python-full": {"ext": ".py", "entry_default": "main.py", "image": "pct-python-full:latest", "run": ["python", "-u", "/work/{main}"], "label": "Python 3.11 full"},
    "javascript": {"ext": ".js", "entry_default": "main.js", "image": "node:20-slim", "run": ["node", "/work/{main}"], "label": "Node.js 20"},
    "bash": {"ext": ".sh", "entry_default": "main.sh", "image": "bash:5", "run": ["bash", "/work/{main}"], "label": "Bash 5"},
    "sh": {"ext": ".sh", "entry_default": "main.sh", "image": "alpine:3.19", "run": ["sh", "/work/{main}"], "label": "POSIX shell"},
    "ruby": {"ext": ".rb", "entry_default": "main.rb", "image": "ruby:3.3-slim", "run": ["ruby", "/work/{main}"], "label": "Ruby 3.3"},
}
DEFAULT_TIMEOUT, MAX_TIMEOUT = 30, 300
MAX_CODE_SIZE, MAX_TOTAL_SIZE, MAX_FILES = 2 * 1024 * 1024, 10 * 1024 * 1024, 100
MAX_OUTPUT, MAX_MEMORY_MB = 4 * 1024 * 1024, 1024
DEFAULT_MEMORY_MB, DEFAULT_CPUS, MAX_CPUS = 512, 1.0, 2.0
DOCKER_PULL_TIMEOUT = 180


def docker_available():
    try: return bool(shutil.which("docker")) and subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=5).returncode == 0
    except Exception: return False


def image_present(image):
    try: return subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True, timeout=10).returncode == 0
    except Exception: return False


def pull_image(image):
    try:
        p = subprocess.run(["docker", "pull", image], capture_output=True, text=True, timeout=DOCKER_PULL_TIMEOUT)
        return p.returncode == 0, (p.stderr or "")[:400]
    except Exception as exc: return False, str(exc)


def available_languages():
    docker = docker_available()
    return {k: {"available": docker, "docker": docker, "image": v["image"], "present": docker and image_present(v["image"]), "label": v["label"]} for k, v in LANGUAGES.items()}


def _sanitize_filename(name):
    if not isinstance(name, str) or not name.strip(): return None
    parts = [p.replace("..", "_") for p in name.replace("\\", "/").strip().lstrip("/").split("/") if p not in ("", ".", "..")]
    return "/".join(parts)[:200] or None


def _validate_inputs(params):
    files, code = params.get("files"), params.get("code")
    output = []
    if files:
        if not isinstance(files, list) or len(files) > MAX_FILES: raise ValueError(f"files يتجاوز الحد ({MAX_FILES})")
        for i, item in enumerate(files):
            if not isinstance(item, dict): raise ValueError(f"file #{i} غير صالح")
            name = _sanitize_filename(item.get("name")); content = item.get("content", "")
            if not name or not isinstance(content, str): raise ValueError(f"file #{i} غير صالح")
            if len(content) > MAX_CODE_SIZE: raise ValueError(f"file #{i} يتجاوز الحد")
            output.append({"name": name, "content": content})
    elif isinstance(code, str) and code:
        if len(code) > MAX_CODE_SIZE: raise ValueError("code يتجاوز الحد")
        output.append({"name": "_legacy_main", "content": code})
    if not output: raise ValueError("code أو files مطلوب")
    if sum(len(item["content"]) for item in output) > MAX_TOTAL_SIZE: raise ValueError("الحجم الإجمالي يتجاوز الحد")
    return output


def _resolve_entry(lang, files, entry):
    if entry:
        entry = _sanitize_filename(entry)
        if not entry or entry not in {f["name"] for f in files}: raise ValueError("entry غير موجود")
        return entry
    if len(files) == 1 and files[0]["name"] == "_legacy_main": return f"__main__{LANGUAGES[lang]['ext']}"
    names = {f["name"] for f in files}
    if LANGUAGES[lang]["entry_default"] in names: return LANGUAGES[lang]["entry_default"]
    if len(files) == 1: return files[0]["name"]
    for item in files:
        if item["name"].endswith(LANGUAGES[lang]["ext"]): return item["name"]
    raise ValueError("لم أجد ملف entry مناسبًا")


def _make_tar(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for item in files:
            if item["name"] == "_legacy_main": continue
            raw = item["content"].encode("utf-8"); info = tarfile.TarInfo(item["name"]); info.size = len(raw); info.mode = 0o644
            archive.addfile(info, io.BytesIO(raw))
    return buffer.getvalue()


def _sast_analysis(files, lang):
    if lang not in ("python", "python-full"): return {"applied": False, "reason": "غير متاح لهذه اللغة"}
    from . import code_reviewer
    findings = []
    for item in files:
        if item["name"].endswith(".py"):
            findings.extend(code_reviewer.scan_code_text(item["content"], filename=item["name"]))
    return {"applied": True, "total": len(findings), "findings": findings[:200], "truncated": len(findings) > 200}


def _syntax_check(files, lang, entry):
    if lang not in ("python", "python-full"): return {"applied": False}
    for item in files:
        if item["name"] == entry or item["name"].endswith(".py"):
            try: ast.parse(item["content"])
            except SyntaxError as exc: return {"applied": True, "ok": False, "error": f"{item['name']}:{exc.lineno}: {exc.msg}"}
    return {"applied": True, "ok": True}


def _run_docker(lang, files, entry, timeout, max_output, memory_mb=DEFAULT_MEMORY_MB, cpus=DEFAULT_CPUS, do_sast=True):
    cfg, image = LANGUAGES[lang], LANGUAGES[lang]["image"]
    if not image_present(image):
        ok, error = pull_image(image)
        if not ok: return {"ok": False, "mode": "docker", "error": f"فشل تنزيل الصورة {image}: {error}"}
    sast = _sast_analysis(files, lang) if do_sast else {"applied": False}
    syntax = _syntax_check(files, lang, entry)
    if syntax.get("applied") and not syntax.get("ok"):
        return {"ok": False, "mode": "docker", "image": image, "error": f"Syntax error: {syntax['error']}", "sast": sast, "syntax_check": syntax, "stdout": "", "stderr": "", "exit_code": None}
    memory = f"{max(64, min(int(memory_mb), MAX_MEMORY_MB))}m"; cpus = str(max(.1, min(float(cpus), MAX_CPUS)))
    command = ["docker", "run", "--rm", "-i", "--network=none", "--memory", memory, "--memory-swap", memory, "--cpus", cpus, "--pids-limit", "128", "--read-only", "--tmpfs", "/work:size=128m,mode=1777", "--tmpfs", "/tmp:size=64m,mode=1777", "--cap-drop=ALL", "--security-opt=no-new-privileges", "-w", "/work", image, "sh", "-c", f"mkdir -p /work && tar -xf - -C /work && exec {' '.join(cfg['run']).replace('{main}', entry)}"]
    start = time.time()
    try:
        proc = subprocess.run(command, input=_make_tar(files), capture_output=True, timeout=timeout + 20)
        stdout_raw, stderr_raw = proc.stdout or b"", proc.stderr or b""
        stdout = stdout_raw.decode("utf-8", "ignore") if isinstance(stdout_raw, bytes) else str(stdout_raw)
        stderr = stderr_raw.decode("utf-8", "ignore") if isinstance(stderr_raw, bytes) else str(stderr_raw)
        return {"ok": True, "mode": "docker", "image": image, "entry": entry, "file_count": len(files), "exit_code": proc.returncode, "stdout": stdout[:max_output], "stderr": stderr[:max_output], "elapsed": round(time.time()-start, 3), "sast": sast, "syntax_check": syntax, "truncated": len(stdout)>max_output or len(stderr)>max_output}
    except subprocess.TimeoutExpired: return {"ok": False, "mode": "docker", "image": image, "error": f"Timeout after {timeout}s", "sast": sast, "syntax_check": syntax}
    except Exception as exc: return {"ok": False, "mode": "docker", "error": str(exc), "sast": sast, "syntax_check": syntax}


def run_code(job, params):
    lang=(params.get("language") or "python").lower()
    if lang not in LANGUAGES: raise ValueError(f"لغة غير مدعومة: {lang}")
    if not docker_available(): raise RuntimeError("Docker غير متوفر — code runner يتطلب Docker")
    files=_validate_inputs(params); entry=_resolve_entry(lang, files, params.get("entry"))
    if files[0]["name"] == "_legacy_main": files[0]["name"] = entry
    try: timeout=max(1,min(int(params.get("timeout",DEFAULT_TIMEOUT)),MAX_TIMEOUT))
    except (TypeError,ValueError): timeout=DEFAULT_TIMEOUT
    try: memory=int(params.get("memory_mb",DEFAULT_MEMORY_MB))
    except (TypeError,ValueError): memory=DEFAULT_MEMORY_MB
    try: cpus=float(params.get("cpus",DEFAULT_CPUS))
    except (TypeError,ValueError): cpus=DEFAULT_CPUS
    try: output=max(1024,min(int(params.get("max_output",MAX_OUTPUT)),MAX_OUTPUT))
    except (TypeError,ValueError): output=MAX_OUTPUT
    result=_run_docker(lang,files,entry,timeout,output,memory,cpus,bool(params.get("analyze",True)))
    result["language"]=lang
    return result
