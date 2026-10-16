# -*- coding: utf-8 -*-
import time
from .correlation_engine import CorrelationEngine
from .suggestion_engine import SuggestionEngine
class UnifiedScanner:
 def __init__(self,correlator=None,suggester=None):self.correlator=correlator or CorrelationEngine();self.suggester=suggester or SuggestionEngine()
 def scan(self,target,modules,options=None,progress_cb=None):
  options=options or {};results={};errors=[];run=[]
  for i,module in enumerate(modules or [],1):
   if progress_cb:progress_cb(module,int((i-1)*100/max(1,len(modules))),f'running {module}')
   try:
    if module=='code':
     from engine import code_reviewer;cfg=options.get('code',{});results['code']=code_reviewer.scan_code(None,{'code':cfg.get('code'),'files':cfg.get('files',[]),'filename':cfg.get('filename')});results['code_text']=cfg.get('code','');run.append(module)
    elif module=='deps':
     from engine import dependency_scanner;cfg=options.get('deps',{});results['deps']=dependency_scanner.scan_requirements_content(cfg.get('content',''),cfg.get('filename','inline.txt'));run.append(module)
    elif module=='osint':
     from engine import osint_dns;cfg=options.get('osint',{});results['osint']=osint_dns.run_osint(None,{'target':target,'ssl':cfg.get('ssl',True),'whois':cfg.get('whois',False),'wellknown':cfg.get('wellknown',False)});run.append(module)
    elif module=='subdomains':
     from engine import subdomain_enum;results['subdomains']=subdomain_enum.enumerate_subdomains(None,{'domain':target,'sources':options.get('subdomains',{}).get('sources')});run.append(module)
    else: errors.append({'module':module,'error':'unknown or unsupported module'})
   except Exception as e:errors.append({'module':module,'error':str(e)})
  correlations=self.correlator.correlate_all(results);suggestions=self.suggester.suggest(correlations)
  if progress_cb:progress_cb('done',100,'complete')
  return {'target':target,'modules_requested':modules,'modules_run':run,'errors':errors,'results':results,'correlations':correlations,'suggestions':suggestions,'risk_score':self._risk(correlations),'elapsed':0}
 def _risk(self,items):return min(10.0,sum({'critical':3,'high':1.8,'medium':.8,'low':.3}.get(x.get('severity'),0) for x in items))
