# -*- coding: utf-8 -*-
_SEV={"critical":0,"high":1,"medium":2,"low":3,"info":4}
class SuggestionEngine:
 def suggest(self,correlations):
  out=[]
  for c in correlations or []:
   kind=c.get('type');rank=_SEV.get(c.get('severity','medium'),2)
   if kind=='osint_to_nuclei':
    targets=(c.get('metadata') or {}).get('targets',[])
    if targets:out.append({'priority':rank,'action':'nuclei_scan','target':targets[0],'reason':c.get('title',''),'params':{'targets':targets,'tags':(c.get('metadata') or {}).get('tags',[])},'estimated_seconds':30*len(targets)})
   elif kind=='deps_in_code':
    pkg=(c.get('metadata') or {}).get('package','');out.append({'priority':rank,'action':'upgrade_dependency','target':pkg,'reason':c.get('title',''),'params':{'package':pkg,'recommendation':c.get('recommendation')},'estimated_seconds':5})
  out.sort(key=lambda x:(x['priority'],x['action']))
  for i,item in enumerate(out,1):item['priority']=i
  return out
