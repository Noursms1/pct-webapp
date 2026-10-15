# -*- coding: utf-8 -*-
"""
=============================================================================
 Engine Module: Hash Matcher / Identifier
-----------------------------------------------------------------------------
 - كشف نوع الهاش (MD5, SHA-1, SHA-256, SHA-512, SHA3, CRC32, bcrypt)
 - مطابقة مع قائمة كلمات (Wordlist) بمهلة زمنية ومتابعة تقدّم
 - توليد هاش لنص (Hash Generator)
=============================================================================
"""

import re
import time
import zlib
import hashlib

# (الاسم, الطول, النمط, الخوارزميات المقابلة في hashlib)
HASH_SIGNATURES = [
    ("MD5",      32,  r"^[a-f0-9]{32}$",    ["md5"]),
    ("NTLM",     32,  r"^[a-f0-9]{32}$",    ["md5"]),
    ("SHA-1",    40,  r"^[a-f0-9]{40}$",    ["sha1"]),
    ("SHA-256",  64,  r"^[a-f0-9]{64}$",    ["sha256"]),
    ("SHA3-256", 64,  r"^[a-f0-9]{64}$",    ["sha3_256"]),
    ("SHA-512",  128, r"^[a-f0-9]{128}$",   ["sha512"]),
    ("SHA3-512", 128, r"^[a-f0-9]{128}$",   ["sha3_512"]),
    ("CRC32",    8,   r"^[a-f0-9]{8}$",     ["crc32"]),
    ("bcrypt",   60,  r"^\$2[aby]\$.*$",    ["bcrypt"]),
]

HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")


def detect_hash_type(h):
    """كشف نوع الهاش وإرجاع المرشحين والخوارزميات."""
    h = (h or "").strip()
    if not h:
        return {"valid": False, "reason": "فارغ"}
    if not HEX_RE.match(h) and not h.startswith("$2"):
        return {"valid": False, "reason": "ليس hex صالحاً"}

    length = len(h)
    candidates = [c for c in HASH_SIGNATURES
                  if c[1] == length and re.match(c[2], h, re.IGNORECASE)]
    if not candidates:
        return {"valid": False, "reason": f"الطول {length} غير معروف"}

    algos = []
    for c in candidates:
        for a in c[3]:
            if a not in algos:
                algos.append(a)

    return {
        "valid": True,
        "primary": candidates[0][0],
        "candidates": [c[0] for c in candidates],
        "algos": algos,
        "length": length,
    }


def hash_word(word, algo):
    """حساب هاش كلمة بخوارزمية محددة."""
    data = word.encode("utf-8", errors="ignore")
    try:
        if algo == "md5":
            return hashlib.md5(data).hexdigest()
        if algo == "sha1":
            return hashlib.sha1(data).hexdigest()
        if algo == "sha256":
            return hashlib.sha256(data).hexdigest()
        if algo == "sha512":
            return hashlib.sha512(data).hexdigest()
        if algo == "sha3_256":
            return hashlib.sha3_256(data).hexdigest()
        if algo == "sha3_512":
            return hashlib.sha3_512(data).hexdigest()
        if algo == "crc32":
            return format(zlib.crc32(data) & 0xFFFFFFFF, "08x")
    except Exception:
        return None
    return None


def generate_hashes(text):
    """توليد مجموعة هاشات لنص واحد."""
    out = {}
    for algo in ("md5", "sha1", "sha256", "sha512", "sha3_256", "crc32"):
        v = hash_word(text, algo)
        if v:
            out[algo] = v
    return out


def crack_hash(job, params):
    """
    نقطة دخول المحرك: مطابقة هاش مع قائمة كلمات في الذاكرة.

    params:
      hash       : str
      words      : list[str]
      algos      : list[str]   (اختياري)
      max_seconds: float
    """
    progress = params.get("_progress")
    target = (params.get("hash") or "").strip()
    info = detect_hash_type(target)
    if not info["valid"]:
        raise ValueError(f"هاش غير صالح: {info.get('reason')}")

    words = [w.strip() for w in (params.get("words") or []) if w and w.strip()]
    if not words:
        raise ValueError("لا توجد كلمات للمطابقة.")

    algos = params.get("algos") or [a for a in info["algos"] if a != "bcrypt"]
    max_seconds = float(params.get("max_seconds", 120))

    target_l = target.lower()
    match = None
    tried = 0
    timed_out = False
    start = time.time()

    for i, w in enumerate(words, 1):
        if progress and progress.is_cancelled():
            break
        for algo in algos:
            if hash_word(w, algo) == target_l:
                match = {"word": w, "algo": algo}
                break
        tried = i
        if match:
            break
        if progress and i % 200 == 0:
            progress.update(i * 100.0 / len(words), f"{i}/{len(words)}")
        if time.time() - start > max_seconds:
            timed_out = True
            break

    if progress:
        progress.update(100)

    return {
        "hash": target,
        "hash_type": info["primary"],
        "candidates": info["candidates"],
        "algos_used": algos,
        "words_total": len(words),
        "words_tried": tried,
        "found": bool(match),
        "match": match,
        "elapsed": round(time.time() - start, 3),
        "timed_out": timed_out,
    }


def crack_hash_from_file(job, params):
    """مطابقة هاش مع ملف قائمة كلمات كبير (قراءة سطر بسطر)."""
    progress = params.get("_progress")
    target = (params.get("hash") or "").strip()
    path = params.get("wordlist")
    info = detect_hash_type(target)
    if not info["valid"]:
        raise ValueError(f"هاش غير صالح: {info.get('reason')}")
    if not path:
        raise ValueError("لم يُحدَّد ملف قائمة الكلمات.")

    algos = params.get("algos") or [a for a in info["algos"] if a != "bcrypt"]
    target_l = target.lower()
    match = None
    tried = 0
    start = time.time()

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if progress and progress.is_cancelled():
                break
            w = line.strip()
            if not w:
                continue
            tried += 1
            for algo in algos:
                if hash_word(w, algo) == target_l:
                    match = {"word": w, "algo": algo}
                    break
            if match:
                break
            if progress and tried % 500 == 0:
                progress.update(min(95, tried / 50), f"{tried} كلمة")

    if progress:
        progress.update(100)
    return {
        "hash": target,
        "hash_type": info["primary"],
        "algos_used": algos,
        "words_tried": tried,
        "found": bool(match),
        "match": match,
        "elapsed": round(time.time() - start, 3),
        "source": "file",
    }
