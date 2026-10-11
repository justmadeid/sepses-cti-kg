"""Read-only: how much CVE threat context would be stale/inadmissible if time were ignored.
Association = (CVE, threat entity) via relationship '<x> targets vulnerability'.
Support time = latest published date of reports that reference the relationship.
Usage: python3 -I stale_context_profile.py <project_root>"""
import json, glob, sys, collections, datetime as dt
root = sys.argv[1]
objs = {}
for f in sorted(glob.glob(root + '/data/raw/alienvault/alienvault-split/alienvault-2025-*.json')):
    d = json.load(open(f))
    for o in (d['objects'] if isinstance(d, dict) else d): objs[o['id']] = o
typ = lambda i: i.split('--')[0]
rel_reports = collections.defaultdict(list)
for o in objs.values():
    if o['type'] == 'report' and o.get('published'):
        for r in o.get('object_refs', []):
            if typ(r) == 'relationship': rel_reports[r].append(o['published'][:10])
assoc = collections.defaultdict(list)  # (cve, src_type, src_id) -> [dates]
revoked = total = no_report = 0
for o in objs.values():
    if o['type'] != 'relationship' or o['relationship_type'] != 'targets' or typ(o['target_ref']) != 'vulnerability': continue
    if o['target_ref'] not in objs: continue
    total += 1; revoked += bool(o.get('revoked'))
    dates = rel_reports.get(o['id'], [])
    if not dates: no_report += 1
    key = (objs[o['target_ref']]['name'], typ(o['source_ref']), o['source_ref'])
    assoc[key] += dates or [o.get('created', '')[:10]]
print(f'targets->vulnerability relationships: {total}, revoked: {revoked}, without referencing report: {no_report}')
print('distinct CVE-threat associations:', len(assoc), collections.Counter(k[1] for k in assoc))
for t0 in ('2025-09-30', '2025-12-31'):
    T = dt.date.fromisoformat(t0)
    future = sum(1 for v in assoc.values() if min(v) > t0)
    for w in (90, 180):
        stale = sum(1 for v in assoc.values() if min(v) <= t0 and (T - dt.date.fromisoformat(max(d for d in v if d <= t0))).days > w)
        admissible = sum(1 for v in assoc.values() if min(v) <= t0) - stale
        print(f't0={t0} W={w}d: future-only(leak if ignored)={future} stale(>W)={stale} admissible={admissible} of {len(assoc)}')
