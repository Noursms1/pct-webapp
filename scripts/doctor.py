#!/usr/bin/env python3
import argparse,importlib, json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(ROOT))
class Doctor:
 def __init__(self,verbose=False,force=False):self.verbose=verbose;self.force=force;self.results=[];self.fixes_applied=[];self.fixes_failed=[]
 def add(self,name,status,message,fixable=False):self.results.append({'name':name,'status':status,'message':message,'fixable':fixable})
 def run_checks(self):
  try:
   from engine import languages,rule_engine; languages.reload();self.add('Registry','ok',', '.join(languages.list_names()));r=rule_engine.scan_multi(None,{'files':[{'name':'a.rs','content':'Command::new(x).spawn();'}]});self.add('Rule engine','ok',str(r['by_language']))
  except Exception as e:self.add('Engine','error',str(e))
  self.add('Tests','ok',str((ROOT/'tests').exists()));return self.results
 def apply_fixes(self):return
 def summary(self):return {s:sum(x['status']==s for x in self.results) for s in ('ok','warn','error')}
 def to_dict(self):return {'results':self.results,'applied':self.fixes_applied,'failed':self.fixes_failed,'summary':self.summary()}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');p.add_argument('--fix',action='store_true');p.add_argument('--force',action='store_true');p.add_argument('--json',action='store_true');a=p.parse_args();d=Doctor();d.run_checks();print(json.dumps(d.to_dict(),ensure_ascii=False,indent=2) if a.json else '\n'.join(f"{x['status']}: {x['name']} - {x['message']}" for x in d.results));sys.exit(0 if d.summary()['error']==0 else 1)
