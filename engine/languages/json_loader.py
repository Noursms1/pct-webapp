# -*- coding: utf-8 -*-
import json,re
from pathlib import Path
from .base import Rule,FrameworkPack,LanguageBranch,BestPractice,LanguageModule

def load_from_dict(data):
 def compile_rule(x):return Rule(x['id'],x['name'],x['category'],x['severity'],re.compile(x['pattern'],re.I|re.M),x['desc'],x['fix'],x.get('cwe'),x.get('owasp'),x.get('tags',[]),x.get('framework'),x.get('branch'))
 return LanguageModule(data['name'],data['version'],data['extensions'],data['description'],data['docs_url'],[compile_rule(x) for x in data['security_rules']],[compile_rule(x) for x in data['engineering_rules']],[FrameworkPack(x['name'],x['version'],x['docs_url'],[compile_rule(r) for r in x['rules']]) for x in data['frameworks']],[LanguageBranch(x['name'],x['description'],x['focus'],x['top_risks'],x['rule_ids']) for x in data['branches']],[BestPractice(x['title'],x['description'],x['example_good'],x['example_bad'],x['references']) for x in data['best_practices']])
def load_from_file(path):
 from .spec import validate_spec
 return load_from_dict(validate_spec(json.loads(Path(path).read_text(encoding='utf-8'))))
