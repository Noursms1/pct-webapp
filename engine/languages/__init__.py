# -*- coding: utf-8 -*-
import importlib,pkgutil
from .base import *
_REGISTRY={};_LOADED=False
def _load_all():
 global _LOADED
 if _LOADED:return
 for _,name,_ in pkgutil.iter_modules(__path__):
  if name=='base' or name.startswith('_'):continue
  try:
   mod=importlib.import_module(f'{__name__}.{name}');lang=getattr(mod,'LANGUAGE',None)
   if lang:_REGISTRY[lang.name.lower()]=lang
  except Exception as e: print(f'[languages] failed to load {name}: {e}')
 _LOADED=True
def get(name):_load_all();return _REGISTRY.get((name or '').lower())
def all_languages():_load_all();return dict(_REGISTRY)
def list_names():_load_all();return sorted(_REGISTRY)
def detect(filename):
 _load_all();fn=(filename or '').lower()
 for lang in _REGISTRY.values():
  if any(fn.endswith(ext.lower()) for ext in lang.extensions):return lang.name
 return None
def all_metadata():_load_all();return {k:v.metadata() for k,v in _REGISTRY.items()}
def stats():
 _load_all();return {'languages':len(_REGISTRY),'total_rules':sum(len(x.all_rules()) for x in _REGISTRY.values()),'security_rules':sum(len(x.security_rules) for x in _REGISTRY.values()),'engineering_rules':sum(len(x.engineering_rules) for x in _REGISTRY.values()),'framework_rules':sum(len(f.rules) for x in _REGISTRY.values() for f in x.frameworks),'branches':sum(len(x.branches) for x in _REGISTRY.values()),'names':list_names()}

def cwe_rules(cwe):
    from . import cross_index
    return cross_index.lookup_cwe(cwe)
def owasp_rules(oid):
    from . import cross_index
    return cross_index.lookup_owasp(oid)
def similar_in_other_languages(rule_id):
    from . import cross_index
    return cross_index.similar_rules(rule_id)
def cross_summary():
    from . import cross_index
    return cross_index.summary()
