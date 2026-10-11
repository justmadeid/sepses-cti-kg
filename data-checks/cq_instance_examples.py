"""Read-only: find concrete instances for CQ examples (actor -> CVE -> malware/indicator/sector/location, report dates, KEV).
Usage: python3 -I cq_instance_examples.py <project_root>"""
import json, glob, sys, collections
root = sys.argv[1]
objs = {}
for f in sorted(glob.glob(root + '/data/raw/alienvault/alienvault-split/alienvault-2025-*.json')):
    d = json.load(open(f))
    for o in (d['objects'] if isinstance(d, dict) else d): objs[o['id']] = o
typ = lambda i: i.split('--')[0]
name = lambda i: objs.get(i, {}).get('name', '?')
rels = [o for o in objs.values() if o['type'] == 'relationship']
out = collections.defaultdict(lambda: collections.defaultdict(set))
for r in rels:
    s, t, rt = r['source_ref'], r['target_ref'], r['relationship_type']
    out[s][(rt, typ(t))].add(t)
inc = collections.defaultdict(lambda: collections.defaultdict(set))
for r in rels:
    inc[r['target_ref']][(r['relationship_type'], typ(r['source_ref']))].add(r['source_ref'])
rel_reports = collections.defaultdict(list)
for o in objs.values():
    if o['type'] == 'report':
        for x in o.get('object_refs', []): rel_reports[x].append(o.get('published', '')[:10])
kev = {v['cveID']: v['dateAdded'] for v in json.load(open(root + '/data/raw/official-source-records/nvd-cisa-targeted-t1-v0.1/cisa-known-exploited-vulnerabilities.json'))['vulnerabilities']}
print('Lazarus-like intrusion sets:', [o['name'] for o in objs.values() if o['type'] == 'intrusion-set' and 'lazarus' in o['name'].lower()][:5])
# rank CVEs by richness of actor+malware+sector+location
vul = {i: o['name'] for i, o in objs.items() if o['type'] == 'vulnerability'}
rows = []
for vid, cve in vul.items():
    actors = {name(s) for (rt, st), ss in inc[vid].items() if st == 'intrusion-set' for s in ss}
    mals = {name(s) for (rt, st), ss in inc[vid].items() if st == 'malware' for s in ss}
    secs, locs = set(), set()
    for (rt, st), ss in inc[vid].items():
        if st in ('intrusion-set', 'malware'):
            for s in ss:
                secs |= {name(x) for x in out[s][('targets', 'identity')]}
                locs |= {name(x) for x in out[s][('targets', 'location')]}
    dates = sorted(d for (rt, st), ss in inc[vid].items() for s in ss for d in [] )
    rows.append((len(actors) > 0, len(secs), cve, sorted(actors)[:4], sorted(mals)[:4], sorted(secs)[:5], sorted(locs)[:5], kev.get(cve)))
rows.sort(key=lambda r: (r[0], r[1]), reverse=True)
for r in rows[:12]:
    print(r[2], '| KEV', r[7], '| actors', r[3], '| malware', r[4], '| sectors', r[5], '| loc', r[6])
for cve in ['CVE-2025-8088', 'CVE-2025-64446', 'CVE-2025-0108', 'CVE-2025-53690', 'CVE-2025-4427']:
    vid = next((i for i, n in vul.items() if n == cve), None)
    if not vid: print(cve, 'not in data'); continue
    links = [(rt, st, name(s)) for (rt, st), ss in inc[vid].items() for s in ss if st in ('intrusion-set', 'malware')]
    rdates = sorted({d for (rt, st), ss in inc[vid].items() for s in ss for r in rels if False for d in []})
    # report dates of relationships targeting this CVE
    rd = sorted({d for r in rels if r['target_ref'] == vid for d in rel_reports.get(r['id'], [])})
    print('\n', cve, 'KEV', kev.get(cve), '| links', sorted(set(links))[:8], '| report dates', rd[:3], '...', rd[-3:], 'n=', len(rd))
