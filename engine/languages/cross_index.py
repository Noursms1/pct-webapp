# -*- coding: utf-8 -*-
import json,os
from pathlib import Path
_INDEX_FILE=Path(__file__).resolve().parent/'_generated'/'cross_index.json'
_CACHE={'data':None,'mtime':0.0}
def _load():
 if not _INDEX_FILE.exists():return None
 try:
  mtime=_INDEX_FILE.stat().st_mtime
  if _CACHE['data'] is None or _CACHE['mtime']!=mtime:
   _CACHE['data']=json.loads(_INDEX_FILE.read_text(encoding='utf-8'));_CACHE['mtime']=mtime
  return _CACHE['data']
 except Exception:return None
def available():return _INDEX_FILE.exists()
def summary():
 d=_load()
 if not d:return {'available':False}
 return {'available':True,'generated_at':d.get('generated_at'),'languages_count':d.get('languages_count',0),'rules_total':d.get('rules_total',0),'cwe_count':len(d.get('by_cwe',[])),'owasp_count':len(d.get('by_owasp',[])),'cross_links':len(d.get('cross_links',{}))}
def lookup_cwe(cwe):
 d=_load();return next((x.get('rules',[]) for x in (d or {}).get('by_cwe',[]) if x.get('cwe','').upper()==cwe.upper()),[])
def lookup_owasp(oid):
 d=_load();return next((x.get('rules',[]) for x in (d or {}).get('by_owasp',[]) if x.get('id','').upper()==oid.upper()),[])
def similar_rules(rid):return ((_load() or {}).get('cross_links',{}).get(rid) or {}).get('similar',[])
def by_category(cat):return ((_load() or {}).get('by_category',{}).get(cat,[]))
def list_cwes(limit=100):return [x.get('cwe') for x in (_load() or {}).get('by_cwe',[])[:limit]]
def list_owasp():return [x.get('id') for x in (_load() or {}).get('by_owasp',[])]
