#!/usr/bin/env python3
import argparse,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('name');p.add_argument('extensions',nargs='+');p.add_argument('--version',default='?');a=p.parse_args();name=a.name.lower();out=Path('data/languages');out.mkdir(parents=True,exist_ok=True);data={'name':name,'version':a.version,'extensions':a.extensions,'description':f'{name} language module','security_rules':[],'engineering_rules':[],'frameworks':[],'branches':[],'best_practices':[]};(out/f'{name}.json').write_text(json.dumps(data,indent=2),encoding='utf-8');print(out/f'{name}.json')
