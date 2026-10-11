"""Read-only profile: threat context per CVE in the AlienVault/OpenCTI STIX split files.
Usage: python3 -I threat_context_profile.py <project_root>"""
import json, glob, collections, sys, statistics, datetime as dt
root = sys.argv[1]
objs = {}
for f in sorted(glob.glob(root + '/data/raw/alienvault/alienvault-split/alienvault-2025-*.json')):
    d = json.load(open(f))
    for o in (d['objects'] if isinstance(d, dict) else d):
        objs[o['id']] = o
typ = lambda i: i.split('--')[0]
rels = [o for o in objs.values() if o['type'] == 'relationship']
pair = collections.Counter((typ(r['source_ref']), r['relationship_type'], typ(r['target_ref'])) for r in rels)
print('== relationship patterns (top 25)')
for k, v in pair.most_common(25): print(v, k)
vul = {i: o['name'] for i, o in objs.items() if o['type'] == 'vulnerability'}
ctx = collections.defaultdict(set)
for r in rels:
    for a, b in ((r['source_ref'], r['target_ref']), (r['target_ref'], r['source_ref'])):
        if a in vul and typ(b) in ('intrusion-set', 'malware', 'attack-pattern', 'campaign', 'tool'):
            ctx[vul[a]].add(typ(b))
cves = set(vul.values())
print('\n== direct threat context on CVEs (relationship-level)')
for t in ('intrusion-set', 'malware', 'attack-pattern'):
    print(t, sum(1 for c in cves if t in ctx[c]), '/', len(cves))
# report co-occurrence context
rep_ctx = collections.defaultdict(set); rep_dates = collections.defaultdict(list)
for o in objs.values():
    if o['type'] != 'report': continue
    refs = o.get('object_refs', [])
    types = {typ(r) for r in refs}
    for r in refs:
        if r in vul:
            rep_ctx[vul[r]] |= types & {'intrusion-set', 'malware', 'attack-pattern'}
            rep_dates[vul[r]].append(o.get('published'))
print('\n== report co-occurrence context on CVEs')
for t in ('intrusion-set', 'malware', 'attack-pattern'):
    print(t, sum(1 for c in cves if t in rep_ctx[c]), '/', len(cves))
tg = [r for r in rels if r['relationship_type'] == 'targets']
print('\n== targets relationships', len(tg), collections.Counter(typ(r['target_ref']) for r in tg).most_common())
idents = [o for o in objs.values() if o['type'] == 'identity']
print('identity_class', collections.Counter(o.get('identity_class') for o in idents))
kev = {v['cveID']: v['dateAdded'] for v in json.load(open(root + '/data/raw/official-source-records/nvd-cisa-targeted-t1-v0.1/cisa-known-exploited-vulnerabilities.json'))['vulnerabilities']}
lags = []
for c in cves:
    if c in kev and rep_dates[c]:
        first = min(rep_dates[c])[:10]
        lags.append((dt.date.fromisoformat(first) - dt.date.fromisoformat(kev[c])).days)
print('\n== first CTI report minus KEV dateAdded (days), n=', len(lags))
print('median', statistics.median(lags), 'p10', sorted(lags)[len(lags)//10], 'p90', sorted(lags)[9*len(lags)//10])
print('CVE years', collections.Counter(c.split('-')[1] for c in cves).most_common(12))
