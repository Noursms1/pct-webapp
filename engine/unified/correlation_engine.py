# -*- coding: utf-8 -*-
import re
SERVER_CVE_MAP={'nginx':[{'eq_prefix':(1,14),'cve':'CVE-2019-20372','severity':'medium','tags':['cve']}],'apache':[{'eq':(2,4,49),'cve':'CVE-2021-41773','severity':'critical','tags':['cve']}]}
def version_tuple(v):return tuple(int(x) for x in re.findall(r'\d+',str(v or ''))[:4])
def parse_server_header(v):
 m=re.match(r'^([A-Za-z][\w-]*)/(\d+(?:\.\d+)*)',str(v or '').strip());return (m.group(1).lower(),m.group(2)) if m else (None,None)
def match_server_cves(name,version):
 v=version_tuple(version);out=[]
 for r in SERVER_CVE_MAP.get((name or '').lower(),[]):
  if ('eq' in r and v==r['eq']) or ('eq_prefix' in r and v[:len(r['eq_prefix'])]==r['eq_prefix']):out.append(r)
 return out
def extract_imports(code,language='auto'):
 return {x.split('.')[0].lower() for x in re.findall(r'^(?:from\s+([\w.]+)|import\s+([\w.]+))',code or '',re.M) for x in x if x}
class CorrelationEngine:
 def __init__(self,rule_store=None,db=None):self.db=db
 def correlate_deps_code(self,deps,code,code_text=None):
  out=[];imports=extract_imports(code_text or '')
  for v in (deps or {}).get('vulnerabilities',[]):
   pkg=(v.get('package') or '').lower();hit=pkg in imports or pkg in '\n'.join(str(f.get('snippet','')).lower() for f in (code or {}).get('findings',[]))
   if hit:out.append({'type':'deps_in_code','severity':v.get('severity','high'),'title':f"{pkg} vulnerability in code",'evidence':[v],'recommendation':f"Upgrade {pkg}",'confidence':.95 if pkg in imports else .75})
  return out
 def correlate_osint_nuclei(self,osint,subs=None):
  name,ver=parse_server_header((osint or {}).get('headers',{}).get('Server',''));out=[]
  for hit in match_server_cves(name,ver):out.append({'type':'osint_to_nuclei','severity':hit['severity'],'title':hit['cve'],'metadata':{'cve':hit['cve'],'targets':[(osint or {}).get('host')]+(subs or {}).get('subdomains',[])}})
  return out
 def correlate_all(self,results):return self.correlate_deps_code(results.get('deps'),results.get('code'))+self.correlate_osint_nuclei(results.get('osint'),results.get('subdomains'))
