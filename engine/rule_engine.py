# -*- coding: utf-8 -*-
"""Unified knowledge-base rule engine."""
from . import languages
from .rules_store import RulesStore
from .code_analyzer import analyze_ast
import re
class UnifiedRuleEngine:
 def __init__(self,rules_store=None):self.store=rules_store or RulesStore()
 def scan_file(self,name,content,language=None,include_engineering=True,include_frameworks=True,frameworks_filter=None,branch=None):
  lang_name=language or languages.detect(name); lang=languages.get(lang_name)
  if not lang:return {'language':None,'findings':[]}
  rules=lang.all_rules(include_engineering,include_frameworks)
  if branch:rules=lang.rules_for_branch(branch)
  findings=[]
  for line_no,line in enumerate(content.splitlines(),1):
   for r in rules:
    if r.pattern.search(line):findings.append({'line':line_no,'rule_id':r.id,'type':r.name,'category':r.category,'severity':r.severity,'cwe':r.cwe,'snippet':line.strip()[:120],'desc':r.desc,'fix':r.fix,'language':lang_name,'source':'pack','file':name})
  if lang_name=='python':
   for f in analyze_ast(content):f.update({'language':'python','source':'ast','file':name});findings.append(f)
  seen=set();out=[]
  for f in findings:
   key=(f['line'],f['rule_id'])
   if key not in seen:seen.add(key);out.append(f)
  return {'language':lang_name,'findings':out}
def scan_multi(job,params):
 files=params.get('files') or []
 if not files:raise ValueError('files مطلوبة')
 engine=UnifiedRuleEngine();all_findings=[];results=[]
 for f in files:
  r=engine.scan_file(f.get('name','unknown'),f.get('content',''),params.get('language'));results.append({'file':f.get('name'),'language':r['language'],'findings':r['findings']});all_findings+=r['findings']
 stats={x:0 for x in ('critical','high','medium','low','info')}
 for f in all_findings:stats[f['severity']]=stats.get(f['severity'],0)+1
 return {'files_scanned':len(files),'total_findings':len(all_findings),'severity_stats':stats,'by_language':{},'results':results,'findings':all_findings,'languages_meta':languages.all_metadata()}
