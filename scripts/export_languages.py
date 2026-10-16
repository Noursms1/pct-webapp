#!/usr/bin/env python3
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(ROOT));OUT=ROOT/'data'/'languages'
def main():
 OUT.mkdir(parents=True,exist_ok=True);from engine import languages
 for name in languages.list_names():
  lang=languages.get(name)
  def rule(r):return {'id':r.id,'name':r.name,'category':r.category,'severity':r.severity,'pattern':r.pattern.pattern,'desc':r.desc,'fix':r.fix,'cwe':r.cwe,'owasp':r.owasp,'tags':r.tags}
  data={'name':lang.name,'version':lang.version,'extensions':lang.extensions,'description':lang.description,'docs_url':lang.docs_url,'security_rules':[rule(r) for r in lang.security_rules],'engineering_rules':[rule(r) for r in lang.engineering_rules],'frameworks':[],'branches':[],'best_practices':[]}
  (OUT/f'{name}.json').write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8');print(f'[+] {name}.json')
if __name__=='__main__':main()
