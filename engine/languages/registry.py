# -*- coding: utf-8 -*-
import importlib,pkgutil,threading
from pathlib import Path
from .base import LanguageModule
_LOCK=threading.Lock();_REGISTRY={};_LOADED=False
ROOT=Path(__file__).resolve().parent.parent.parent

def reload():
 global _REGISTRY,_LOADED
 with _LOCK:
  result={}
  for _,name,_ in pkgutil.iter_modules([str(Path(__file__).parent)]):
   if name.startswith('_') or name in {'base','spec','registry','json_loader','cross_index'}:continue
   try:
    mod=importlib.import_module(f'engine.languages.{name}');lang=getattr(mod,'LANGUAGE',None)
    if isinstance(lang,LanguageModule):result[lang.name]=lang
   except Exception as exc:print(f'[registry] {name}: {exc}')
  from .json_loader import load_from_file
  folder=ROOT/'data'/'languages'
  if folder.is_dir():
   for path in folder.glob('*.json'):
    try:
     lang=load_from_file(path);result[lang.name]=lang
    except Exception as exc:print(f'[registry] {path.name}: {exc}')
  _REGISTRY=result;_LOADED=True
 return _REGISTRY

def _ensure():
 if not _LOADED:reload()
def get(name):_ensure();return _REGISTRY.get((name or '').lower())
def all_languages():_ensure();return dict(_REGISTRY)
def list_names():_ensure();return sorted(_REGISTRY)
def detect(filename):
 _ensure();fn=(filename or '').lower()
 for lang in _REGISTRY.values():
  if any(fn.endswith(ext) for ext in lang.extensions):return lang.name
 return None
def all_metadata():_ensure();return {k:v.metadata() for k,v in _REGISTRY.items()}
def all_frameworks():_ensure();return [{'language':l.name,'framework':f.name,'version':f.version,'rules_count':len(f.rules),'docs_url':f.docs_url} for l in _REGISTRY.values() for f in l.frameworks]
def stats():
 _ensure();return {'languages':len(_REGISTRY),'total_rules':sum(len(l.all_rules()) for l in _REGISTRY.values()),'security_rules':sum(len(l.security_rules) for l in _REGISTRY.values()),'engineering_rules':sum(len(l.engineering_rules) for l in _REGISTRY.values()),'framework_rules':sum(len(f.rules) for l in _REGISTRY.values() for f in l.frameworks),'branches':sum(len(l.branches) for l in _REGISTRY.values()),'names':list_names()}
