# -*- coding: utf-8 -*-
import io,re
from pathlib import Path
try:
 import pypdf; HAS_PYPDF=True
except ImportError: HAS_PYPDF=False
MAX_PDF_SIZE=50*1024*1024

def pdf_available(): return HAS_PYPDF
def extract_text_from_pdf(source,max_pages=2000):
 if not HAS_PYPDF:return {"ok":False,"error":"pypdf غير مثبّت"}
 try:
  if isinstance(source,(bytes,bytearray)):
   if len(source)>MAX_PDF_SIZE:return {"ok":False,"error":"PDF كبير جدًا"}
   reader=pypdf.PdfReader(io.BytesIO(source))
  else: reader=pypdf.PdfReader(str(Path(source)))
  texts=[reader.pages[i].extract_text() or "" for i in range(min(len(reader.pages),max_pages))]
  text="\n".join(texts)[:4*1024*1024]
  return {"ok":True,"text":text,"pages":len(texts),"chars":len(text)}
 except Exception as e:return {"ok":False,"error":str(e)}

def _slug(text): return re.sub(r"[^A-Za-z0-9]+","-",text).strip("-").upper()[:40] or "RULE"
def parse_rules_from_text(text,default_language=None):
 rules=[]; refs=[]
 for index,block in enumerate(re.split(r"(?=^\s*(?:Rule|Finding|Issue)\s*[:#])",text or "",flags=re.I|re.M),1):
  header=re.search(r"^(?:Rule|Finding|Issue)\s*[:#]?\s*(.+)$",block,re.I|re.M)
  if not header: continue
  cwe=re.search(r"CWE[-\s]?(\d+)",block,re.I); sev=re.search(r"Severity\s*[:\-]\s*(critical|high|medium|low|info)",block,re.I); pat=re.search(r"(?:Pattern|Regex)\s*[:\-]\s*(.+)",block,re.I); fix=re.search(r"(?:Fix|Remediation)\s*[:\-]\s*(.+)",block,re.I)
  rules.append({"id":f"PDF-{_slug(header.group(1))}-{index}","name":header.group(1).strip()[:80],"severity":(sev.group(1).lower() if sev else "medium"),"cwe":f"CWE-{cwe.group(1)}" if cwe else None,"pattern_raw":pat.group(1).strip() if pat else None,"desc":block[:500],"fix":fix.group(1).strip()[:200] if fix else "Review context","language":default_language,"source":"pdf"})
 for match in re.finditer(r"CWE[-\s]?(\d+)",text or "",re.I): refs.append({"cwe":f"CWE-{match.group(1)}","context":text[max(0,match.start()-80):match.start()+180]})
 return rules,refs
def compile_rule_pattern(raw):
 try:return (re.compile(raw,re.I),None) if raw else (None,"no pattern")
 except re.error as e:return None,str(e)
