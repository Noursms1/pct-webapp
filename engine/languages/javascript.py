# -*- coding: utf-8 -*-
"""JavaScript/TypeScript security and engineering knowledge base."""
from .base import FrameworkPack, LanguageBranch, BestPractice, LanguageModule, sec, eng

SECURITY = [
    sec("JS-SEC-XSS-01","innerHTML assignment","high",r"\.innerHTML\s*=","Direct DOM HTML write.","Use textContent or DOMPurify",cwe="CWE-79"),
    sec("JS-SEC-XSS-02","document.write","high",r"document\.write\s*\(","Raw document write.","Use safe DOM APIs",cwe="CWE-79"),
    sec("JS-SEC-XSS-03","dangerouslySetInnerHTML","high",r"dangerouslySetInnerHTML\s*=","React HTML injection.","Sanitize before rendering",cwe="CWE-79"),
    sec("JS-SEC-XSS-04","v-html","high",r"v-html\s*=","Vue raw HTML injection.","Use v-text or sanitize",cwe="CWE-79"),
    sec("JS-SEC-DOMXSS-01","eval(location)","critical",r"eval\s*\(\s*(?:location|window\.location)","URL data reaches eval.","Never eval URL data",cwe="CWE-95"),
    sec("JS-SEC-EVAL-01","eval","critical",r"\beval\s*\(","Dynamic code execution.","Avoid eval",cwe="CWE-95"),
    sec("JS-SEC-EVAL-02","new Function","critical",r"new\s+Function\s*\(","Dynamic code execution.","Use explicit functions",cwe="CWE-95"),
    sec("JS-SEC-PROTO-01","Prototype pollution","critical",r"\[\s*['\"](?:__proto__|constructor|prototype)['\"]\s*\]","Prototype pollution vector.","Filter dangerous keys",cwe="CWE-1321"),
    sec("JS-SEC-CMDI-01","child_process exec","critical",r"(?:require\s*\(\s*['\"]child_process['\"]\s*\)|\.exec\s*\()","Shell command execution.","Use execFile with args",cwe="CWE-78"),
    sec("JS-SEC-CMDI-02","spawn shell true","critical",r"\.spawn(?:Sync)?\s*\([^)]*shell\s*:\s*true","Shell injection.","Use shell:false",cwe="CWE-78"),
    sec("JS-SEC-SQLI-01","SQL concatenation","critical",r"(?:query|execute)\s*\(\s*['\"`][^'\"`]*['\"`]\s*\+","SQL concatenation.","Use parameterized queries",cwe="CWE-89"),
    sec("JS-SEC-SQLI-02","SQL template interpolation","critical",r"(?:query|execute)\s*\(\s*`[^`]*\$\{","SQL template interpolation.","Use parameters",cwe="CWE-89"),
    sec("JS-SEC-SSRF-01","fetch tainted URL","critical",r"fetch\s*\(\s*(?:req|request|userInput|target)","SSRF risk.","Whitelist destinations",cwe="CWE-918"),
    sec("JS-SEC-SSRF-02","axios tainted URL","critical",r"axios\.(?:get|post|request)\s*\(\s*(?:req|request|target)","SSRF risk.","Validate destination",cwe="CWE-918"),
    sec("JS-SEC-JWT-01","JWT none algorithm","critical",r"algorithm\s*[:=]\s*['\"]none['\"]","JWT signature bypass.","Use explicit algorithms",cwe="CWE-347"),
    sec("JS-SEC-JWT-02","jwt.decode","high",r"jwt\.decode\s*\(","Decode without verification.","Use jwt.verify",cwe="CWE-347"),
    sec("JS-SEC-JWT-03","JWT hardcoded secret","high",r"jwt\.sign\s*\([^)]*['\"][^'\"]{6,}['\"]","Hardcoded JWT secret.","Use environment secrets",cwe="CWE-798"),
    sec("JS-SEC-SECRET-01","Hardcoded secret","high",r"(?:password|apiKey|api_key|secret|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]","Hardcoded credential.","Use process.env",cwe="CWE-798"),
    sec("JS-SEC-SECRET-02","AWS key pattern","critical",r"(?:AKIA|ASIA)[0-9A-Z]{16}","AWS key pattern.","Rotate key",cwe="CWE-798"),
    sec("JS-SEC-CRYPTO-01","Weak hash","medium",r"crypto\.createHash\s*\(\s*['\"](?:md5|sha1)['\"]","Weak hash.","Use sha256+",cwe="CWE-327"),
    sec("JS-SEC-RAND-01","Math.random","medium",r"Math\.random\s*\(\s*\)","Non-crypto random.","Use crypto.randomBytes",cwe="CWE-338"),
    sec("JS-SEC-TLS-01","TLS verification disabled","high",r"rejectUnauthorized\s*:\s*false","TLS bypass.","Keep verification enabled",cwe="CWE-295"),
    sec("JS-SEC-PATH-01","Tainted fs path","high",r"fs\.(?:readFile|readFileSync|createReadStream)\s*\([^)]*(?:req\.|request\.)","Tainted file path.","Validate base path",cwe="CWE-22"),
    sec("JS-SEC-REDIR-01","Open redirect","medium",r"res\.redirect\s*\(\s*(?:req|request)\.","Redirect from request input.","Allowlist local paths",cwe="CWE-601"),
]
ENGINEERING = [
    eng("JS-ENG-EQ-01","Loose equality","low",r"[^=!<>]==[^=]","Type coercion.","Use ==="),
    eng("JS-ENG-VAR-01","var declaration","medium",r"^\s*var\s+","Function scoped var.","Use let/const"),
    eng("JS-ENG-LOG-01","console.log","low",r"^\s*console\.(?:log|debug|info)\s*\(","Production logging.","Use structured logger"),
    eng("JS-ENG-JSON-01","JSON.parse without handling","medium",r"JSON\.parse\s*\(","May throw on invalid input.","Use try/catch"),
    eng("JS-ENG-ANY-01","TypeScript any","low",r":\s*any\b","Disables type checking.","Use unknown or precise types"),
    eng("JS-ENG-INDEX-KEY-01","React index key","medium",r"key\s*=\s*\{\s*(?:i|idx|index)\s*\}","Unstable React key.","Use stable IDs"),
    eng("JS-ENG-TODO-01","TODO marker","info",r"//\s*(?:TODO|FIXME|XXX)\b","Unresolved marker.","Create issue"),
    eng("JS-ENG-PROMISE-01","Promise without catch","medium",r"\.then\s*\([^)]*\)\s*;","Unhandled rejection risk.","Add catch"),
    eng("JS-ENG-RANDOM-01","Empty callback","low",r"=>\s*\{\s*\}","Empty callback.","Implement or remove"),
    eng("JS-ENG-LOOP-01","for-in array","low",r"for\s*\(\s*(?:const|let|var)\s+\w+\s+in\s+\w+","Inherited keys included.","Use for-of"),
    eng("JS-ENG-ASYNC-01","Async without await","low",r"async\s+function\s+\w+[^{}]*\{\s*return","Review unnecessary async.","Remove async or await"),
    eng("JS-ENG-HTTP-01","HTTP request without timeout","low",r"axios\.(?:get|post)\s*\(","Verify request timeout.","Set timeout"),
    eng("JS-ENG-MUTATE-01","Direct state mutation","medium",r"state\.\w+\s*=","Direct state mutation.","Use immutable updates"),
    eng("JS-ENG-OPTIONAL-01","Deep optional access","low",r"\.\w+\.\w+\.\w+","May throw on undefined.","Use optional chaining"),
    eng("JS-ENG-TODO-02","debugger statement","low",r"\bdebugger\s*;","Debugger left in source.","Remove debugger"),
]
COMMON_FW=[sec("JS-FW-AUTH-01","Auth route needs rate limit","high",r"(?:app|router)\.post\s*\(\s*['\"][^'\"]*(?:login|auth|register)","Auth route needs rate limiting.","Apply rate limiter",cwe="CWE-307")]
EXPRESS=FrameworkPack("Express","4.x/5.x","https://expressjs.com/",COMMON_FW)
REACT=FrameworkPack("React","18.x","https://react.dev/",[sec("JS-REACT-01","dangerouslySetInnerHTML","high",r"dangerouslySetInnerHTML\s*=","Raw HTML sink.","Sanitize HTML",cwe="CWE-79"),eng("JS-REACT-02","Index key","medium",r"key\s*=\s*\{\s*index\s*\}","Unstable key.","Use stable ID")])
VUE=FrameworkPack("Vue","3.x","https://vuejs.org/",[sec("JS-VUE-01","v-html","high",r"v-html\s*=","Raw HTML.","Use v-text",cwe="CWE-79")])
NEXT=FrameworkPack("Next.js","14.x","https://nextjs.org/",[sec("JS-NEXT-01","Env leak","high",r"getServerSideProps[\s\S]{0,300}process\.env","Server env leak.","Return public values",cwe="CWE-200")])
NODE=FrameworkPack("Node.js","20.x","https://nodejs.org/",[sec("JS-NODE-01","Dynamic require","critical",r"require\s*\(\s*(?:req|request|userInput)","Dynamic module loading.","Use allowlist",cwe="CWE-829")])
BRANCHES=[LanguageBranch("web_frontend","Browser applications",focus=["XSS","DOM"],top_risks=["XSS"],rule_ids=["JS-SEC-XSS-01","JS-SEC-DOMXSS-02"]),LanguageBranch("web_backend","APIs",focus=["Auth","SSRF"],top_risks=["SQLi","SSRF"],rule_ids=["JS-SEC-SQLI-01","JS-SEC-SSRF-01"]),LanguageBranch("fullstack","Next.js apps",focus=["Server routes"],top_risks=["Env leak"],rule_ids=["JS-NEXT-01"]),LanguageBranch("automation_scripts","CLI and CI",focus=["Commands"],top_risks=["RCE"],rule_ids=["JS-SEC-CMDI-01"]),LanguageBranch("electron_desktop","Electron",focus=["IPC"],top_risks=["RCE"],rule_ids=["JS-SEC-EVAL-01"]),LanguageBranch("typescript_typed","Typed JS",focus=["Types"],top_risks=["any"],rule_ids=["JS-ENG-ANY-01"])]
BEST_PRACTICES=[BestPractice("Sanitize HTML","Never inject untrusted HTML.","textContent","innerHTML"),BestPractice("Parameterized SQL","Use placeholders.","query('...', [x])","query(`...${x}`)")]
LANGUAGE=LanguageModule("javascript","ES2023+ / Node 20+",[".js",".mjs",".cjs",".jsx",".ts",".tsx"],"JavaScript and TypeScript security knowledge base",security_rules=SECURITY,engineering_rules=ENGINEERING,frameworks=[EXPRESS,REACT,VUE,NEXT,NODE],branches=BRANCHES,best_practices=BEST_PRACTICES)
