#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline-first cross-language CWE/OWASP rule harvester."""
import argparse, json, sys
from datetime import datetime, timezone
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / 'engine' / 'languages' / '_generated'
INDEX = OUT / 'cross_index.json'
META = OUT / 'sources_meta.json'
CWE_TOP = [{"cwe": c, "name": n, "rank": i} for i, (c, n) in enumerate([('CWE-79','XSS'),('CWE-89','SQL Injection'),('CWE-22','Path Traversal'),('CWE-78','OS Command Injection'),('CWE-502','Deserialization'),('CWE-918','SSRF'),('CWE-798','Hardcoded Credentials'),('CWE-327','Weak Cryptography'),('CWE-295','TLS Bypass'),('CWE-338','Weak Randomness'),('CWE-352','CSRF'),('CWE-200','Information Exposure'),('CWE-306','Missing Authentication'),('CWE-862','Missing Authorization'),('CWE-611','XXE'),('CWE-95','Code Injection'),('CWE-400','Resource Exhaustion'),('CWE-117','Log Injection'),('CWE-347','JWT Failure'),('CWE-470','Unsafe Reflection'),('CWE-434','Unrestricted Upload'),('CWE-20','Input Validation'),('CWE-190','Integer Overflow'),('CWE-416','Use After Free'),('CWE-787','Out of Bounds Write')], 1)]
OWASP = [{"id": f"A{i:02d}:2021", "name": n} for i, n in enumerate(['Broken Access Control','Cryptographic Failures','Injection','Insecure Design','Security Misconfiguration','Vulnerable Components','Authentication Failures','Integrity Failures','Logging Failures','SSRF'], 1)]
OWASP_CWE = {
 'A01:2021': {'CWE-22','CWE-352','CWE-862','CWE-863','CWE-434'},
 'A02:2021': {'CWE-295','CWE-327','CWE-338','CWE-347','CWE-798'},
 'A03:2021': {'CWE-20','CWE-77','CWE-78','CWE-79','CWE-89','CWE-90','CWE-94','CWE-95','CWE-98','CWE-918'},
 'A04:2021': {'CWE-306','CWE-287','CWE-400'},
 'A05:2021': {'CWE-200','CWE-611','CWE-942','CWE-489'},
 'A06:2021': {'CWE-937','CWE-1035','CWE-1104'},
 'A07:2021': {'CWE-287','CWE-295','CWE-306','CWE-307','CWE-346','CWE-798'},
 'A08:2021': {'CWE-502','CWE-494','CWE-829'},
 'A09:2021': {'CWE-117','CWE-200'},
 'A10:2021': {'CWE-918'},
}


def build():
    from engine import languages
    by_cwe, by_owasp, cats, links = {}, {}, {}, {}
    for name in languages.list_names():
        mod = languages.get(name)
        for rule in mod.all_rules():
            data = rule.to_dict()
            item = {'language': name, 'rule_id': data['id'], 'name': data['name'], 'severity': data['severity'], 'cwe': data.get('cwe')}
            if data.get('cwe'): by_cwe.setdefault(data['cwe'], []).append(item)
            direct = data.get('owasp')
            direct_ids = [direct] if isinstance(direct, str) else list(direct or [])
            derived_ids = [oid for oid, cwes in OWASP_CWE.items() if data.get('cwe') in cwes]
            for oid in sorted(set(direct_ids + derived_ids)):
                by_owasp.setdefault(oid, []).append({**item, 'source': 'direct' if oid in direct_ids else 'derived'})
            cats.setdefault(data.get('category', 'unknown'), []).append({'language': name, 'rule_id': data['id']})

    for cwe, items in by_cwe.items():
        for item in items: links[item['rule_id']] = {'cwe': cwe, 'similar': [x for x in items if x['rule_id'] != item['rule_id']]}
    owasp_entries = []
    for item in OWASP:
        rules = by_owasp.get(item['id'], [])
        owasp_entries.append({**item, 'rule_count': len(rules), 'direct_count': sum(x.get('source') == 'direct' for x in rules), 'derived_count': sum(x.get('source') == 'derived' for x in rules), 'language_count': len({x['language'] for x in rules}), 'rules': rules})
    assignments = sum(len(x['rules']) for x in owasp_entries)
    print(f"    OWASP distribution: {assignments} rule assignments")
    index = {'generated_at': datetime.now(timezone.utc).isoformat(), 'languages_count': len(languages.list_names()), 'rules_total': sum(len(l.all_rules()) for l in languages.all_languages().values()), 'by_cwe': [{'cwe': c['cwe'], 'name': c['name'], 'rank_top25': c['rank'], 'rule_count': len(by_cwe.get(c['cwe'], [])), 'language_count': len({x['language'] for x in by_cwe.get(c['cwe'], [])}), 'rules': by_cwe.get(c['cwe'], [])} for c in CWE_TOP], 'by_owasp': owasp_entries, 'by_category': cats, 'cross_links': links, 'online': {'enabled': False, 'errors': []}}
    OUT.mkdir(parents=True, exist_ok=True); INDEX.write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding='utf-8'); META.write_text(json.dumps({'generated_at': index['generated_at'], 'languages': index['languages_count'], 'rules_total': index['rules_total']}, indent=2), encoding='utf-8'); return index

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--rebuild', action='store_true'); parser.add_argument('--status', action='store_true'); parser.add_argument('--update', action='store_true'); parser.add_argument('--check', action='store_true'); parser.add_argument('--export', choices=['cwe','owasp','index']); parser.add_argument('--lookup-cwe'); parser.add_argument('--lookup-owasp'); args = parser.parse_args()
    if args.rebuild or args.update:
        x = build(); print(f"languages={x['languages_count']} rules={x['rules_total']}"); return 0
    if not INDEX.exists(): print('cross_index missing'); return 1
    x = json.loads(INDEX.read_text(encoding='utf-8'))
    if args.status: print(json.dumps({'languages': x['languages_count'], 'rules': x['rules_total'], 'cwe': len(x['by_cwe']), 'owasp': len(x['by_owasp']), 'cross_links': len(x['cross_links'])}, indent=2)); return 0
    if args.lookup_cwe or args.lookup_owasp:
        key, field = (args.lookup_cwe.upper(), 'cwe') if args.lookup_cwe else (args.lookup_owasp.upper(), 'id'); group = 'by_cwe' if args.lookup_cwe else 'by_owasp'; print(json.dumps(next((item for item in x[group] if item[field] == key), {}), ensure_ascii=False, indent=2)); return 0
    if args.check: print('OK'); return 0
    if args.export: print(json.dumps(CWE_TOP if args.export == 'cwe' else OWASP if args.export == 'owasp' else x, ensure_ascii=False)); return 0
    parser.print_help(); return 0

if __name__ == '__main__': sys.exit(main())

