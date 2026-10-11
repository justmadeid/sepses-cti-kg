"""Read-only: how discriminative is 'sector relevance' for CVEs under two definitions.
(A) transitive: CVE <-targets- actor/malware -targets-> sector (graph-wide, merged across reports)
(B) report-scoped: a single report references both the CVE and the sector identity.
Also: Lazarus chain example. Usage: python3 -I relevance_discrimination.py <project_root>"""
import json, glob, sys, collections
root = sys.argv[1]
objs = {}
for f in sorted(glob.glob(root + '/data/raw/alienvault/alienvault-split/alienvault-2025-*.json')):
    d = json.load(open(f))
    for o in (d['objects'] if isinstance(d, dict) else d): objs[o['id']] = o
typ = lambda i: i.split('--')[0]
name = lambda i: objs.get(i, {}).get('name', '?')
rels = [o for o in objs.values() if o['type'] == 'relationship']
out = collections.defaultdict(set); inc = collections.defaultdict(set)
for r in rels:
    out[r['source_ref']].add((r['relationship_type'], r['target_ref'])); inc[r['target_ref']].add((r['relationship_type'], r['source_ref']))
vul = {i: o['name'] for i, o in objs.items() if o['type'] == 'vulnerability'}
sectors = {i: o['name'] for i, o in objs.items() if o['type'] == 'identity' and o.get('identity_class') == 'class'}
A = collections.defaultdict(set)
for vid in vul:
    for rt, s in inc[vid]:
        if typ(s) in ('intrusion-set', 'malware'):
            A[vid] |= {t for rt2, t in out[s] if rt2 == 'targets' and t in sectors}
B = collections.defaultdict(set)
for o in objs.values():
    if o['type'] != 'report': continue
    refs = set(o.get('object_refs', []))
    for v in refs & vul.keys(): B[v] |= refs & sectors.keys()
n = len(vul)
for label, M in (('A transitive', A), ('B report-scoped', B)):
    sizes = sorted(len(M[v]) for v in vul)
    print(f'{label}: CVEs with >=1 sector {sum(1 for v in vul if M[v])}/{n}; median sectors/CVE {sizes[n//2]}; max {sizes[-1]}')
    for sec in ('Government', 'Education', 'Finance', 'Technology'):
        sid = [i for i, nm in sectors.items() if nm == sec]
        c = sum(1 for v in vul if M[v] & set(sid))
        print(f'   {sec}: {c}/{n} CVEs ({100*c/n:.1f}%)')
# Lazarus chain
laz = [i for i, o in objs.items() if o['type'] == 'intrusion-set' and 'lazarus' in o['name'].lower()]
for l in laz[:5]:
    mals = sorted({name(t) for rt, t in out[l] if typ(t) == 'malware'})
    cves = sorted({name(t) for rt, t in out[l] if typ(t) == 'vulnerability'})
    aps = sorted({name(t) for rt, t in out[l] if typ(t) == 'attack-pattern'})[:3]
    inds = sum(1 for rt, s in inc[l] if typ(s) == 'indicator')
    secs = sorted({name(t) for rt, t in out[l] if t in sectors})[:6]
    print(f'\n{name(l)}: uses malware {mals[:5]} | targets CVE {cves[:5]} | techniques e.g. {aps} | indicators->actor {inds} | sectors {secs}')
    for m in [t for rt, t in out[l] if typ(t) == 'malware'][:2]:
        mi = [s for rt, s in inc[m] if typ(s) == 'indicator' and rt == 'indicates']
        ex = objs[mi[0]]['pattern'][:90] if mi else None
        print(f'   malware {name(m)}: {len(mi)} indicators, e.g. {ex}')
