# -*- coding: utf-8 -*-
"""Built-in strict language rule packs."""
import re

def _r(i,n,s,c,p,d="Strict security rule",f="Review and remediate this pattern"):
    return {"id":i,"name":n,"severity":s,"cwe":c,"pattern":re.compile(p,re.I),"desc":d,"fix":f}

PYTHON_RULES=[_r("PY-SQLI-01","SQL Injection","critical","CWE-89",r"execute\s*\([^)]*(?:\+|f[\"'])"),_r("PY-CMDI-01","Command Injection","critical","CWE-78",r"os\.(?:system|popen)\s*\("),_r("PY-CMDI-02","subprocess shell=True","critical","CWE-78",r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True"),_r("PY-EVAL-01","eval/exec","critical","CWE-95",r"\b(?:eval|exec)\s*\("),_r("PY-DESER-01","Unsafe deserialization","critical","CWE-502",r"(?:pickle\.loads?|yaml\.load)\s*\("),_r("PY-SECRET-01","Hardcoded secret","high","CWE-798",r"(?:password|secret|token|api_key)\s*=\s*[\"'][^\"']{3,}[\"']"),_r("PY-PATH-01","Path traversal","high","CWE-22",r"open\s*\([^)]*\.\./"),_r("PY-WEAKCRYPTO-01","Weak hash","medium","CWE-327",r"hashlib\.(?:md5|sha1)\s*\("),_r("PY-RANDOM-01","Insecure random","medium","CWE-338",r"random\.(?:random|randint|choice)\s*\("),_r("PY-TLSVERIFY-01","TLS verify disabled","medium","CWE-295",r"verify\s*=\s*False")]

def _pack(prefix, lang, specs, exts): return {"rules":[_r(f"{prefix}-{i:02d}",n,s,c,p) for i,(n,s,c,p) in enumerate(specs,1)],"ext":exts}
COMMON=[("XSS","high","CWE-79",r"innerHTML\s*=|document\.write"),("Command injection","critical","CWE-78",r"(?:system|exec|popen)\s*\("),("Hardcoded secret","high","CWE-798",r"(?:password|secret|token|api_key)\s*[:=]\s*[\"'][^\"']{5,}"),("Unsafe eval","critical","CWE-95",r"\beval\s*\("),("Weak crypto","medium","CWE-327",r"(?:md5|sha1)"),("Insecure random","medium","CWE-338",r"(?:Math\.random|random\()"),("TLS bypass","high","CWE-295",r"(?:verify|InsecureSkipVerify|rejectUnauthorized)\s*[:=]\s*false"),("Path traversal","high","CWE-22",r"\.\./"),("Unsafe deserialization","critical","CWE-502",r"(?:unserialize|pickle|ObjectInputStream)"),("SQL injection","critical","CWE-89",r"(?:query|execute)\s*\([^)]*\+")]
LANGUAGE_PACKS={"python":{"rules":PYTHON_RULES,"ext":[".py"]}}
for key,prefix,exts in [("javascript","JS",[".js",".mjs",".ts",".jsx",".tsx"]),("php","PHP",[".php"]),("java","JAVA",[".java"]),("go","GO",[".go"]),("ruby","RB",[".rb"]),("csharp","CS",[".cs"]),("cpp","CPP",[".c",".cpp",".cc",".h",".hpp"]),("sql","SQL",[".sql"]),("shell","SH",[".sh",".bash",".zsh"] )]: LANGUAGE_PACKS[key]=_pack(prefix,key,COMMON,exts)

def get_pack(lang): return LANGUAGE_PACKS.get((lang or "").lower())
def detect_language(filename):
    name=(filename or "").lower()
    for lang,pack in LANGUAGE_PACKS.items():
        if any(name.endswith(ext) for ext in pack["ext"]): return lang
    return None
def all_packs_metadata():
    return {k:{"count":len(v["rules"]),"extensions":v["ext"],"rules":[{x:y for x,y in r.items() if x!="pattern"} for r in v["rules"]]} for k,v in LANGUAGE_PACKS.items()}
def scan_with_language(text,language):
    pack=get_pack(language); out=[]
    if not pack:return out
    for line_no,line in enumerate(text.splitlines(),1):
        for r in pack["rules"]:
            if r["pattern"].search(line): out.append({"line":line_no,"rule_id":r["id"],"type":r["name"],"severity":r["severity"],"cwe":r["cwe"],"snippet":line.strip()[:120],"desc":r["desc"],"fix":r["fix"],"language":language})
    return out
