import json,glob,collections,sys
root=sys.argv[1]
vul={};reports=[]
for f in sorted(glob.glob(root+'/data/raw/alienvault/alienvault-split/alienvault-2025-*.json')):
    d=json.load(open(f)); objs=d['objects'] if isinstance(d,dict) else d
    for o in objs:
        if o['type']=='vulnerability': vul[o['id']]=o['name']
        elif o['type']=='report': reports.append((o.get('published'),o.get('created_by_ref'),o.get('object_refs',[])))
pubs=sorted(r[0] for r in reports if r[0]); print('reports',len(reports),'published range',pubs[0],pubs[-1])
by_year=collections.Counter(p[:4] for p in pubs); print('by year',sorted(by_year.items()))
print('distinct created_by',len(set(r[1] for r in reports)))
first=collections.defaultdict(list)
for p,c,refs in reports:
    for r in refs:
        if r in vul: first[vul[r]].append(p)
kev={v['cveID']:v['dateAdded'] for v in json.load(open(root+'/data/raw/official-source-records/nvd-cisa-targeted-t1-v0.1/cisa-known-exploited-vulnerabilities.json'))['vulnerabilities']}
cves=set(vul.values()); ink=[c for c in cves if c in kev]
print('cves',len(cves),'in KEV',len(ink))
before=after=0
for c in ink:
    fp=min(first[c]) if first[c] else None
    if fp is None: continue
    if fp[:10] < kev[c]: before+=1
    else: after+=1
print('first CTI report before KEV add:',before,' on/after:',after)
cnt=collections.Counter(len(first[c]) for c in cves); print('reports-per-CVE dist (top)',sorted(cnt.items())[:12])
