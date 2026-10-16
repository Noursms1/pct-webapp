# -*- coding: utf-8 -*-
import json,os
from pathlib import Path
INDEX=Path(__file__).resolve().parent/'_generated'/'cross_index.json'
def _load():
 if not INDEX.exists():return None
 try:return json.loads(INDEX.read_text(encoding='utf-8'))
 except Exception:return None
def available():return INDEX.exists()
def summary():
 d=_load()
 return {'available':True,'languages_count':d['languages_count'],'rules_total':d['rules_total'],'cwe_count':len(d['by_cwe']),'cross_links':len(d['cross_links'])} if d else {'available':False}
def lookup_cwe(cwe):
 d=_load();return next((x['rules'] for x in (d or {}).get('by_cwe',[]) if x['cwe']==cwe.upper()),[])
def lookup_owasp(oid):
 d=_load();return next((x['rules'] for x in (d or {}).get('by_owasp',[]) if x['id']==oid.upper()),[])
def similar_rules(rule_id):return (( _load() or {}).get('cross_links',{}).get(rule_id) or {}).get('similar',[])
def by_category(cat):return ((_load() or {}).get('by_category',{}).get(cat,[]))
