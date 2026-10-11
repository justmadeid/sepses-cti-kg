"""Read-only: candidate positives for a point-in-time KEV-based outcome label.
For cutoff t0: CVEs mentioned in CTI reports published <= t0 and NOT in KEV at t0;
positive if added to KEV in (t0, t0+window]. Also ransomware flag counts.
Usage: python3 -I kev_label_windows.py <project_root>"""
import json, glob, sys, collections, datetime as dt
root = sys.argv[1]
objs = {}
for f in sorted(glob.glob(root + '/data/raw/alienvault/alienvault-split/alienvault-2025-*.json')):
    d = json.load(open(f))
    for o in (d['objects'] if isinstance(d, dict) else d): objs[o['id']] = o
vul = {i: o['name'] for i, o in objs.items() if o['type'] == 'vulnerability'}
first = {}
for o in objs.values():
    if o['type'] == 'report' and o.get('published'):
        for r in o.get('object_refs', []):
            if r in vul:
                c = vul[r]; p = o['published'][:10]
                first[c] = min(first.get(c, p), p)
kevall = json.load(open(root + '/data/raw/official-source-records/nvd-cisa-targeted-t1-v0.1/cisa-known-exploited-vulnerabilities.json'))['vulnerabilities']
kev = {v['cveID']: v['dateAdded'] for v in kevall}
rw = collections.Counter(v['knownRansomwareCampaignUse'] for v in kevall if v['cveID'] in set(vul.values()))
print('KEV ransomware flag among CTI CVEs in KEV:', dict(rw))
D = dt.date.fromisoformat
for t0 in ('2025-04-30', '2025-06-30', '2025-08-31', '2025-10-31'):
    cand = [c for c, p in first.items() if p <= t0 and not (c in kev and kev[c] <= t0)]
    for w in (90, 180, 365):
        end = (D(t0) + dt.timedelta(days=w)).isoformat()
        pos = [c for c in cand if c in kev and t0 < kev[c] <= end]
        censored = end > '2026-08-27'
        print(f't0={t0} window={w:>3}d candidates={len(cand):>3} positives={len(pos):>2}' + ('  (window extends past KEV snapshot 2026-08-27: censored)' if censored else ''))
yr = collections.Counter(v['dateAdded'][:4] for v in kevall)
print('KEV additions per year (catalog 2026-08-27):', sorted(yr.items())[-5:])
