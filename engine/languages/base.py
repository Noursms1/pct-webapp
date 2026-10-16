# -*- coding: utf-8 -*-
from dataclasses import dataclass, field
import re
SEVERITIES=("critical","high","medium","low","info")
SEVERITY_ORDER={s:i for i,s in enumerate(SEVERITIES)}
@dataclass
class Rule:
 id:str; name:str; category:str; severity:str; pattern:object; desc:str; fix:str; cwe:str=None; owasp:str=None; tags:list=field(default_factory=list); framework:str=None; branch:str=None
 def to_dict(self): return {k:getattr(self,k) for k in ('id','name','category','severity','desc','fix','cwe','owasp','tags','framework','branch')}
@dataclass
class FrameworkPack:
 name:str; version:str; docs_url:str=''; rules:list=field(default_factory=list)
 def to_dict(self): return {'name':self.name,'version':self.version,'docs_url':self.docs_url,'rules_count':len(self.rules),'rules':[r.to_dict() for r in self.rules]}
@dataclass
class LanguageBranch:
 name:str; description:str; focus:list=field(default_factory=list); top_risks:list=field(default_factory=list); rule_ids:list=field(default_factory=list)
 def to_dict(self): return {'name':self.name,'description':self.description,'focus':self.focus,'top_risks':self.top_risks,'rule_ids':self.rule_ids}
@dataclass
class BestPractice:
 title:str; description:str; example_good:str=''; example_bad:str=''; references:list=field(default_factory=list)
 def to_dict(self): return self.__dict__.copy()
@dataclass
class LanguageModule:
 name:str; version:str; extensions:list; description:str; docs_url:str=''; security_rules:list=field(default_factory=list); engineering_rules:list=field(default_factory=list); frameworks:list=field(default_factory=list); branches:list=field(default_factory=list); best_practices:list=field(default_factory=list)
 def all_rules(self,include_engineering=True,include_frameworks=True): return self.security_rules+(self.engineering_rules if include_engineering else [])+[r for f in self.frameworks if include_frameworks for r in f.rules]
 def rules_by_id(self): return {r.id:r for r in self.all_rules()}
 def rules_for_framework(self,name): return next((f.rules for f in self.frameworks if f.name.lower()==(name or '').lower()),[])
 def rules_for_branch(self,name):
  b=next((x for x in self.branches if x.name==name),None); ids=set(b.rule_ids) if b else set(); return [r for r in self.all_rules() if r.id in ids]
 def metadata(self): return {'name':self.name,'version':self.version,'extensions':self.extensions,'description':self.description,'docs_url':self.docs_url,'counts':{'security':len(self.security_rules),'engineering':len(self.engineering_rules),'frameworks':len(self.frameworks),'framework_rules':sum(len(f.rules) for f in self.frameworks),'branches':len(self.branches),'total_rules':len(self.all_rules())},'frameworks':[f.name for f in self.frameworks],'branches':[b.name for b in self.branches]}
def rule(id,name,category,severity,pattern,desc,fix,cwe=None,owasp=None,tags=None,framework=None,branch=None): return Rule(id,name,category,severity,re.compile(pattern,re.I|re.M),desc,fix,cwe,owasp,tags or [],framework,branch)
def sec(id,name,severity,pattern,desc,fix,cwe=None,owasp=None,**kw): return rule(id,name,'security',severity,pattern,desc,fix,cwe,owasp,**kw)
def eng(id,name,severity,pattern,desc,fix,**kw): return rule(id,name,'engineering',severity,pattern,desc,fix,**kw)
def perf(id,name,severity,pattern,desc,fix,**kw): return rule(id,name,'performance',severity,pattern,desc,fix,**kw)
def style(id,name,severity,pattern,desc,fix,**kw): return rule(id,name,'style',severity,pattern,desc,fix,**kw)
