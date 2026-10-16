#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline-first cross-language CWE/OWASP rule harvester."""
import argparse,json,sys
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent; OUT=ROOT/'engine'/'languages'/'_generated'; INDEX=OUT/'cross_index.json'; META=OUT/'sources_meta.json'
CWE_TOP=[{"cwe":x,"name":n,"rank":i} for i,(x,n) in enumerate([('CWE-79','XSS'),('CWE-89','SQL Injection'),('CWE-22','Path Traversal'),('CWE-78','OS Command Injection'),('CWE-502','Deserialization'),('CWE-918','SSRF'),('CWE-798','Hardcoded Credentials'),('CWE-327','Weak Cryptography'),('CWE-295','TLS Bypass'),('CWE-338','Weak Randomness'),('CWE-352','CSRF'),('CWE-200','Information Exposure'),('CWE-306','Missing Authentication'),('CWE-862','Missing Authorization'),('CWE-611','XXE'),('CWE-95','Code Injection'),('CWE-400','Resource Exhaustion'),('CWE-117','Log Injection'),('CWE-347','JWT Failure'),('CWE-470','Unsafe Reflection'),('CWE-434','Unrestricted Upload'),('CWE-20','Input Validation'),('CWE-190','Integer Overflow'),('CWE-416','Use After Free'),('CWE-787','Out of Bounds Write')],1)]
OWASP=[{"id":f"A{i:02d}:2021","name":n} for i,n in enumerate(['Broken Access Control','Cryptographic Failures','Injection','Insecure Design','Security Misconfiguration','Vulnerable Components','Authentication Failures','Integrity Failures','Logging Failures','SSRF'],1)]
def build():
 from engine import languages
 langs={}; by_cwe={}; by_owasp={}; cats={}; links={}
 for name in languages.list_names():
  mod=languages.get(name); rules=[r.to_dict() for r in mod.all_rules()]; langs[name]={'metadata':mod.metadata(),'rules':rules}
  for r in rules:
   if r.get('cwe'):by_cwe.setdefault(r['cwe'],[]).append({'language':name,'rule_id':r['id'],'name':r['name'],'severity':r['severity']})
   if r.get('owasp'):by_owasp.setdefault(r['owasp'],[]).append({'language':name,'rule_id':r['id'],'name':r['name'],'severity':r['severity']})
   cats.setdefault(r.get('category','unknown'),[]).append({'language':name,'rule_id':r['id']})
 for cwe,items in by_cwe.items():
  for item in items: links[item['rule_id']]={'cwe':cwe,'similar':[x for x in items if x['rule_id']!=item['rule_id']]}
 index={'generated_at':datetime.now(timezone.utc).isoformat(),'languages_count':len(langs),'rules_total':sum(len(x['rules']) for x in langs.values()),'by_cwe':[{'cwe':c['cwe'],'name':c['name'],'rank_top25':c['rank'],'rule_count':len(by_cwe.get(c['cwe'],[])),'language_count':len({x['language'] for x in by_cwe.get(c['cwe'],[])}),'rules':by_cwe.get(c['cwe'],[])} for c in CWE_TOP],'by_owasp':[{'id':x['id'],'name':x['name'],'rules':by_owasp.get(x['id'],[])} for x in OWASP],'by_category':cats,'cross_links':links,'online':{'enabled':False,'errors':[]}}
 OUT.mkdir(parents=True,exist_ok=True);INDEX.write_text(json.dumps(index,ensure_ascii=False,indent=2),encoding='utf-8');META.write_text(json.dumps({'generated_at':index['generated_at'],'languages':index['languages_count'],'rules_total':index['rules_total']},indent=2),encoding='utf-8');return index
def main():
 p=argparse.ArgumentParser();p.add_argument('--rebuild',action='store_true');p.add_argument('--status',action='store_true');p.add_argument('--check',action='store_true');p.add_argument('--lookup-cwe');p.add_argument('--export',choices=['cwe','owasp','index']);a=p.parse_args()
 if a.rebuild:
  x=build();print(f"languages={x['languages_count']} rules={x['rules_total']}");return 0
 if not INDEX.exists():print('cross_index missing');return 1
 x=json.loads(INDEX.read_text(encoding='utf-8'))
 if a.status: print(json.dumps({'languages':x['languages_count'],'rules':x['rules_total'],'cwe':len(x['by_cwe']),'owasp':len(x['by_owasp']),'cross_links':len(x['cross_links'])},indent=2));return 0
 if a.lookup_cwe:
  c=next((z for z in x['by_cwe'] if z['cwe']==a.lookup_cwe.upper()),None);print(json.dumps(c or {},ensure_ascii=False,indent=2));return 0
 if a.check: print('OK');return 0
 if a.export: print(json.dumps(CWE_TOP if a.export=='cwe' else OWASP if a.export=='owasp' else x,ensure_ascii=False));return 0
 p.print_help();return 0
if __name__=='__main__':sys.exit(main())
