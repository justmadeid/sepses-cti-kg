"""Read-only: is there enough month-by-month CVE x sector/location signal for a temporal evaluation label?
Usage: python3 -I temporal_label_feasibility.py <project_root>"""
import json, glob, collections, sys
root = sys.argv[1]
objs = {}
for f in sorted(glob.glob(root + '/data/raw/alienvault/alienvault-split/alienvault-2025-*.json')):
    d = json.load(open(f))
    for o in (d['objects'] if isinstance(d, dict) else d):
        objs[o['id']] = o
typ = lambda i: i.split('--')[0]
vul = {i: o['name'] for i, o in objs.items() if o['type'] == 'vulnerability'}
name = lambda i: objs[i].get('name', '?') if i in objs else '?'
month_cves = collections.defaultdict(set); month_reports = collections.Counter()
cve_months = collections.defaultdict(set)
sector_pairs = collections.defaultdict(set); loc_pairs = collections.defaultdict(set)
for o in objs.values():
    if o['type'] != 'report' or not o.get('published'): continue
    m = o['published'][:7]; refs = o.get('object_refs', [])
    cv = [vul[r] for r in refs if r in vul]
    if not cv: continue
    month_reports[m] += 1
    secs = [name(r) for r in refs if typ(r) == 'identity']
    locs = [name(r) for r in refs if typ(r) == 'location']
    for c in cv:
        month_cves[m].add(c); cve_months[c].add(m)
        for s in secs: sector_pairs[m].add((c, s))
        for l in locs: loc_pairs[m].add((c, l))
print('month  reports_with_cve  distinct_cves  cve-sector_pairs  cve-location_pairs')
for m in sorted(month_reports):
    print(m, month_reports[m], len(month_cves[m]), len(sector_pairs[m]), len(loc_pairs[m]))
rec = collections.Counter(len(v) for v in cve_months.values())
print('\nCVE seen in N distinct months:', sorted(rec.items()))
# recurrence: CVEs seen up to 2025-06 that reappear after 2025-06
early = {c for c, ms in cve_months.items() if any(m <= '2025-06' for m in ms)}
late = {c for c, ms in cve_months.items() if any(m > '2025-06' for m in ms)}
print('seen<=Jun:', len(early), ' seen>Jun:', len(late), ' both:', len(early & late), ' new-after-Jun:', len(late - early))
allsec = collections.Counter(s for m in sector_pairs for _, s in sector_pairs[m])
print('\ntop sectors', allsec.most_common(12))
allloc = collections.Counter(l for m in loc_pairs for _, l in loc_pairs[m])
print('top locations', allloc.most_common(12))
print('Indonesia pairs:', sum(1 for m in loc_pairs for _, l in loc_pairs[m] if 'Indonesia' in l))
