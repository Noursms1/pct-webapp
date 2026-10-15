# -*- coding: utf-8 -*-
"""
=============================================================================
 Engine Module: Secure Code Reviewer
-----------------------------------------------------------------------------
 تحليل الأكواد بحثاً عن أنماط ثغرات شائعة (SAST خفيف بمحرك قواعد قابل للتوسيع)
=============================================================================
"""

import re

from .code_analyzer import analyze_ast


# ===========================================================================
# Rule Engine / محرك القواعد
# ===========================================================================
# كل قاعدة: id, name, severity, cwe, pattern, desc, fix, languages (اختياري)

CODE_RULES = [
    {
        "id": "SQLI",
        "name": "SQL Injection",
        "severity": "critical",
        "cwe": "CWE-89",
        "pattern": re.compile(
            r"""(?:execute|executemany)\s*\(\s*(?:.+?\+\s*.+|f["'].+?\{.+?\}|.+?%\s*.+|.+?\.format\s*\()""",
            re.IGNORECASE,
        ),
        "desc": "استعلام SQL يتم بناؤه بشكل مباشر من متغيرات => ثغرة حقن SQL.",
        "fix": "استخدم Parameterized Queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
    },
    {
        "id": "XSS",
        "name": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "cwe": "CWE-79",
        "pattern": re.compile(
            r"""(?:innerHTML\s*=|document\.write\s*\(|render_template_string\s*\()""",
            re.IGNORECASE,
        ),
        "desc": "إدخال غير مُنقّى في HTML/DOM => ثغرة XSS.",
        "fix": "استخدم textContent / Jinja2 autoescape: element.textContent = userInput;",
    },
    {
        "id": "CMDI",
        "name": "Command Injection",
        "severity": "critical",
        "cwe": "CWE-78",
        "pattern": re.compile(
            r"""(?:os\.system\s*\(|subprocess\.(?:call|Popen|run|check_output)\s*\([^)]*\+|subprocess\.(?:call|Popen|run)\s*\([^)]*shell\s*=\s*True)""",
            re.IGNORECASE,
        ),
        "desc": "تنفيذ أوامر نظام بمتغيرات مباشرة => ثغرة Command Injection.",
        "fix": "استخدم subprocess بقائمة args و shell=False: subprocess.run(['ping','-c','1',host])",
    },
    {
        "id": "SECRET",
        "name": "Hardcoded Secret",
        "severity": "high",
        "cwe": "CWE-798",
        # (?<![A-Za-z0-9]) بدل \b لكي يُطابق DB_PASSWORD و API_TOKEN أيضاً
        "pattern": re.compile(
            r"""(?<![A-Za-z0-9])(?:[A-Za-z0-9_]*)?(?:password|passwd|pwd|api_key|apikey|secret|token|access_key)\s*=\s*["'][^"']{3,}["']""",
            re.IGNORECASE,
        ),
        "desc": "بيانات حساسة مكتوبة بشكل صريح في الكود (Hardcoded).",
        "fix": "استخدم متغيرات البيئة / Secrets Manager: password = os.getenv('DB_PASSWORD')",
    },
    {
        "id": "PATH",
        "name": "Path Traversal",
        "severity": "high",
        "cwe": "CWE-22",
        "pattern": re.compile(r"""open\s*\([^)]*(?:\.\./|\.\.\\\\)""", re.IGNORECASE),
        "desc": "فتح ملفات بمسارات مبنية من مدخلات => Path Traversal.",
        "fix": "ثبّت المسار داخل مجلد آمن: safe = os.path.join(BASE_DIR, os.path.basename(name))",
    },
    {
        "id": "EVAL",
        "name": "Dangerous eval/exec",
        "severity": "high",
        "cwe": "CWE-95",
        "pattern": re.compile(r"""\b(?:eval|exec)\s*\(\s*[^)"']*[a-zA-Z_]"""),
        "desc": "استخدام eval/exec على مدخلات => تنفيذ كود عشوائي.",
        "fix": "استخدم ast.literal_eval() للبيانات البنيوية أو خريطة تحويل صريحة.",
    },
    {
        "id": "DESER",
        "name": "Unsafe Deserialization",
        "severity": "critical",
        "cwe": "CWE-502",
        "pattern": re.compile(r"""(?:pickle\.loads?|yaml\.load\s*\(|marshal\.loads?)\s*\("""),
        "desc": "فك تسلسل غير آمن (pickle/yaml.load) => RCE محتمل.",
        "fix": "استخدم yaml.safe_load() أو json، ولا تفكّك تسلسل بيانات غير موثوقة.",
    },
    {
        "id": "WEAKCRYPTO",
        "name": "Weak Cryptography",
        "severity": "medium",
        "cwe": "CWE-327",
        "pattern": re.compile(
            r"""\b(?:hashlib\.(?:md5|sha1)|DES|RC4|Blowfish)\s*\(""", re.IGNORECASE
        ),
        "desc": "استخدام خوارزمية هاش/تشفير ضعيفة (MD5/SHA1/DES).",
        "fix": "استخدم hashlib.sha256 / bcrypt / argon2 أو AES-GCM للتشفير.",
    },
    {
        "id": "DEBUG",
        "name": "Debug Mode Enabled",
        "severity": "medium",
        "cwe": "CWE-489",
        "pattern": re.compile(r"""app\.run\s*\([^)]*debug\s*=\s*True""", re.IGNORECASE),
        "desc": "تشغيل السيرفر في وضع التصحيح => تسريب معلومات وتنفيذ كود.",
        "fix": "اجعل debug=False في الإنتاج واستخدم متغير بيئة للتحكم.",
    },
    {
        "id": "TLSVERIFY",
        "name": "Disabled TLS Verification",
        "severity": "medium",
        "cwe": "CWE-295",
        "pattern": re.compile(r"""\bverify\s*=\s*False"""),
        "desc": "تعطيل التحقق من شهادة TLS => قابلية لهجوم MITM.",
        "fix": "لا تعطّل verify؛ إن كان الشهادة ذاتية التوقيع أضفها إلى CA bundle.",
    },
    {
        "id": "RANDOM",
        "name": "Insecure Randomness",
        "severity": "medium",
        "cwe": "CWE-338",
        "pattern": re.compile(r"""\brandom\.(?:random|randint|choice|randrange)\s*\("""),
        "desc": "استخدام random غير التشفيري لتوليد قيم أمنية (توكن/كلمة مرور).",
        "fix": "استخدم secrets.token_urlsafe() / secrets.token_hex().",
    },
    {
        "id": "BINDALL",
        "name": "Bind to All Interfaces",
        "severity": "low",
        "cwe": "CWE-1327",
        "pattern": re.compile(r"""\bhost\s*=\s*["']0\.0\.0\.0["']"""),
        "desc": "الاستماع على كل الواجهات => تعريض الخدمة للشبكة الخارجية.",
        "fix": "استمع على 127.0.0.1 إن كانت الخدمة محلية فقط.",
    },
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# امتدادات تُعامل كملفات كود عند رفع مجلد
CODE_EXTENSIONS = {
    ".py", ".js", ".mjs", ".ts", ".jsx", ".tsx", ".php", ".rb", ".java",
    ".go", ".c", ".cpp", ".cs", ".sh", ".sql", ".html", ".jsp", ".asp",
    ".aspx", ".yml", ".yaml", ".env", ".ini", ".conf", ".tf", ".pl",
}


def rules_metadata():
    """إرجاع بيانات القواعد بدون الكائنات المترجمة (للواجهة)."""
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "severity": r["severity"],
            "cwe": r["cwe"],
            "desc": r["desc"],
            "fix": r["fix"],
        }
        for r in CODE_RULES
    ]


def _mask_secret(snippet):
    """إخفاء القيمة الحساسة داخل المقطع المعروض."""
    return re.sub(
        r"""(["'])([^"']{3,})\1""",
        lambda m: m.group(1) + (m.group(2)[:2] + "*" * max(0, len(m.group(2)) - 2)) + m.group(1),
        snippet,
    )


def _dedup_regex_and_ast(findings):
    seen = {}
    for finding in findings:
        rule_id = (finding.get("rule_id") or finding.get("type") or "").replace("_AST", "")
        key = (finding.get("line"), rule_id.lower())
        if key not in seen:
            seen[key] = finding
    return list(seen.values())


def scan_code_text(code_text, filename=None):
    """فحص نص كود واحد وإرجاع قائمة النتائج."""
    findings = []
    lines = code_text.splitlines()
    for ln_idx, line in enumerate(lines, start=1):
        stripped = line.rstrip()
        for rule in CODE_RULES:
            m = rule["pattern"].search(stripped)
            if not m:
                continue
            snippet = stripped.strip()[:120]
            if rule["id"] == "SECRET":
                snippet = _mask_secret(snippet)
            findings.append(
                {
                    "file": filename,
                    "line": ln_idx,
                    "rule_id": rule["id"],
                    "type": rule["name"],
                    "severity": rule["severity"],
                    "cwe": rule["cwe"],
                    "column": m.start() + 1,
                    "snippet": snippet,
                    "desc": rule["desc"],
                    "fix": rule["fix"],
                }
            )
    ast_findings = analyze_ast(code_text)
    for finding in ast_findings:
        finding["file"] = filename
    merged = _dedup_regex_and_ast(findings + ast_findings)
    merged.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    return merged


def scan_code(job, params):
    """
    نقطة دخول المحرك: فحص كود نصي أو مجموعة ملفات.

    params:
      code    : str  -> النص المباشر
      files   : list -> [{"name": "...", "content": "..."}] ملفات متعددة
    """
    progress = params.get("_progress")
    files = params.get("files") or []
    code = params.get("code")

    targets = []
    if code:
        targets.append((params.get("filename") or "inline_code", code))
    for f in files:
        if f.get("content") is not None:
            targets.append((f.get("name") or "unnamed", f["content"]))

    if not targets:
        raise ValueError("لا يوجد كود لتحليله.")

    all_findings = []
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_lines = 0

    for i, (name, content) in enumerate(targets, 1):
        if progress and progress.is_cancelled():
            break
        found = scan_code_text(content, filename=name)
        all_findings.extend(found)
        total_lines += len(content.splitlines())
        for f in found:
            stats[f["severity"]] = stats.get(f["severity"], 0) + 1
        if progress:
            progress.update(i * 90 / len(targets), f"تحليل {name}")

    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    if progress:
        progress.update(100)

    files_scanned = len(targets)
    return {
        "files_scanned": files_scanned,
        "lines": total_lines,
        "total_findings": len(all_findings),
        "severity_stats": stats,
        "risk_level": _risk_level(all_findings),
        "findings": all_findings,
    }


def _risk_level(findings):
    if not findings:
        return "none"
    top = min(SEVERITY_ORDER.get(f["severity"], 9) for f in findings)
    return ["critical", "high", "medium", "low", "info"][top]
