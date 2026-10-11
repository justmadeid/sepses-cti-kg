"""Read-only: worked example facts for CQ1-CQ8 (CVE-2025-64446, CVE-2025-8088) + Lazarus aliases.
Usage: python3 -I cq_worked_example.py <project_root>"""
import json, glob, sys, collections, os
root = sys.argv[1]
objs = {}
for f in sorted(glob.glob(root + '/data/raw/alienvault/alienvault-split/alienvault-2025-*.json')):
    d = json.load(open(f))
    for o in (d['objects'] if isinstance(d, dict) else d): objs[o['id']] = o
typ = lambda i: i.split('--')[0]
name = lambda i: objs.get(i, {}).get('name', '?')
rels = [o for o in objs.values() if o['type'] == 'relationship']
reports_of = collections.defaultdict(list)
for o in objs.values():
    if o['type'] == 'report':
        for x in o.get('object_refs', []): reports_of[x].append(o)
kev = {v['cveID']: v for v in json.load(open(root + '/data/raw/official-source-records/nvd-cisa-targeted-t1-v0.1/cisa-known-exploited-vulnerabilities.json'))['vulnerabilities']}
sectors = {i for i, o in objs.items() if o['type'] == 'identity' and o.get('identity_class') == 'class'}
def cve_record(cve):
    y, n = cve.split('-')[1], cve.split('-')[2]
    p = glob.glob(f"{root}/data/raw/cve-list-v5/{y}/{n[:-3]}xxx/{cve}.json")
    if not p: return None
    r = json.load(open(p[0])); cna = r['containers']['cna']
    aff = [(a.get('vendor'), a.get('product'), [(v.get('version'), v.get('lessThan') or v.get('lessThanOrEqual'), v.get('status')) for v in a.get('versions', [])][:3], a.get('defaultStatus')) for a in cna.get('affected', [])][:2]
    cvss = [m for c in [cna] + r['containers'].get('adp', []) for m in c.get('metrics', [])]
    sc = [(k, v.get('baseScore'), v.get('baseSeverity')) for m in cvss for k, v in m.items() if k.startswith('cvss')][:2]
    cwe = sorted({d.get('cweId') for p in cna.get('problemTypes', []) for d in p.get('descriptions', []) if d.get('cweId')})
    cpe = sum(1 for a in cna.get('affected', []) for _ in a.get('cpes', []))
    return dict(published=r['cveMetadata'].get('datePublished', '')[:10], affected=aff, cvss=sc, cwe=cwe, explicit_cpe=cpe)
for cve in ('CVE-2025-64446', 'CVE-2025-8088'):
    vid = next(i for i, o in objs.items() if o['type'] == 'vulnerability' and o['name'] == cve)
    print('\n=====', cve)
    print(' CVE record:', cve_record(cve))
    k = kev.get(cve); print(' KEV:', k and (k['dateAdded'], k['vendorProject'], k['product'], k['knownRansomwareCampaignUse']))
    for r in rels:
        if r['target_ref'] != vid: continue
        reps = reports_of.get(r['id'], [])
        print(f"  {name(r['source_ref'])} ({typ(r['source_ref'])}) -{r['relationship_type']}-> {cve} | reports: " +
              '; '.join(f"{x.get('published','')[:10]} '{x.get('name','')[:60]}' by {name(x.get('created_by_ref'))}" for x in reps[:2]))
    reps = reports_of.get(vid, [])
    for x in reps[:4]:
        secs = sorted(name(s) for s in x.get('object_refs', []) if s in sectors)
        locs = sorted(name(s) for s in x.get('object_refs', []) if typ(s) == 'location')
        print(f"  report {x.get('published','')[:10]} '{x.get('name','')[:70]}': sectors {secs[:6]} | locations {locs[:6]}")
print('\n===== Lazarus aliases and external ids')
for i, o in objs.items():
    if o['type'] == 'intrusion-set' and 'lazarus' in o['name'].lower():
        ext = [(e.get('source_name'), e.get('external_id')) for e in o.get('external_references', []) if e.get('external_id')][:3]
        print(' ', o['name'], '| aliases', (o.get('aliases') or [])[:4], '| ext', ext)
