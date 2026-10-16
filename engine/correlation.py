# -*- coding: utf-8 -*-
def correlate(results):
 findings=[]
 for module,data in (results or {}).items():
  for item in (data.get('findings') or []): findings.append({'source':module,**item})
 return {'findings':findings,'total':len(findings),'risk':'critical' if any(x.get('severity')=='critical' for x in findings) else 'none','by_severity':{}}
