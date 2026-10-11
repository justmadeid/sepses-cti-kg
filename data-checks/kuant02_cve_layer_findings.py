"""KUANT-02 (read-only): ukur temuan prototipe KG v0.1 pada lapisan CVE.

  A. Cakupan CVE yang disebut CTI per tahun ID: CVE List v5 lokal (D4), seed SEPSES
     converter (D2, NVD 1.1 2021-2024), dan dump SEPSES IFS 2019 (D3).
  B. Ketersediaan CVSS: v3.x, v4.0, dan CVE yang HANYA punya v4.0 (celah kosakata SEPSES).
  C. defaultStatus entri affected dan bentuk entri versi (dasar logika tiga nilai).

Usage: python3 -I kuant02_cve_layer_findings.py <project_root>
"""
import collections
import glob
import gzip
import json
import os
import re
import sys

root = sys.argv[1]
pct = lambda a, b: f"{a}/{b} ({100 * a / b:.1f}%)" if b else f"{a}/0"
CVE_RE = re.compile(rb'resource/cve/(CVE-\d{4}-\d{4,})')            # seed converter: IRI penuh
DUMP_RE = re.compile(rb'(CVE-\d{4}-\d{4,})\s+rdf:type\s+\w+:CVE\b')  # dump 2019: nama berprefiks bertipe CVE

# CVE yang disebut CTI (D1)
cti = set()
for f in sorted(glob.glob(root + '/data/raw/alienvault/alienvault-split/alienvault-2025-*.json')):
    d = json.load(open(f))
    for o in (d['objects'] if isinstance(d, dict) else d):
        if o['type'] == 'vulnerability':
            m = re.match(r'(CVE-\d{4}-\d{4,})', o['name'].upper())
            if m:
                cti.add(m.group(1))
print(f"CVE unik yang disebut CTI (D1): {len(cti)}")

# D4: CVE List v5 lokal
d4_files = glob.glob(root + '/data/raw/cve-list-v5/*/*/CVE-*.json')
d4 = {os.path.basename(p)[:-5]: p for p in d4_files}
print(f"D4 CVE List v5 lokal: {len(d4)} rekaman; tahun direktori: {sorted({p.split('/')[-3] for p in d4_files})}")

# D2/D3: SEPSES seed dan dump (dibaca sebagai teks, hanya mencari IRI CVE)
seed_root = root + '/belajar-kg/code-references/pengembangan-dari-base/[kelompok-2]SPARQL-MCP/main/sparqlmcp-main/database/seed data'
d2, d3 = set(), set()
for p in glob.glob(glob.escape(seed_root) + '/**/*', recursive=True):
    name = os.path.basename(p)
    if name.startswith('nvdcve-1.1-') and name.endswith('.ttl'):
        with open(p, 'rb') as fh:
            for chunk in iter(lambda: fh.read(1 << 24), b''):
                d2.update(m.decode() for m in CVE_RE.findall(chunk))
    elif name.startswith('graph') and name.endswith('.ttl.gz') and 'cpe' not in name and 'capec' not in name and 'cwe' not in name:
        with gzip.open(p, 'rb') as fh:
            for chunk in iter(lambda: fh.read(1 << 24), b''):
                d3.update(m.decode() for m in DUMP_RE.findall(chunk))
print(f"D2 seed SEPSES (NVD 1.1): {len(d2)} CVE | D3 dump SEPSES 2019: {len(d3)} CVE")

# ---------------------------------------------------------------- A. cakupan per tahun
print("\n=== A. Cakupan CVE CTI per tahun ID")
by_year = collections.defaultdict(list)
for c in cti:
    by_year[c.split('-')[1]].append(c)
print(f"  {'tahun':6s} {'n':>4s} {'D4':>4s} {'D2':>4s} {'D3':>4s} {'salah satu':>10s}")
tot = collections.Counter()
for y in sorted(by_year):
    cs = by_year[y]
    row = dict(n=len(cs), D4=sum(c in d4 for c in cs), D2=sum(c in d2 for c in cs), D3=sum(c in d3 for c in cs),
               any=sum((c in d4) or (c in d2) or (c in d3) for c in cs))
    tot.update(row)
    print(f"  {y:6s} {row['n']:4d} {row['D4']:4d} {row['D2']:4d} {row['D3']:4d} {row['any']:10d}")
print(f"  {'total':6s} {tot['n']:4d} {tot['D4']:4d} {tot['D2']:4d} {tot['D3']:4d} {tot['any']:10d}  -> tercakup {pct(tot['any'], tot['n'])}")
pre = [c for c in cti if c.split('-')[1] < '2025']
print("  CVE CTI sebelum 2025:", len(pre), "| tercakup D2/D3:", pct(sum((c in d2) or (c in d3) for c in pre), len(pre)))

# ---------------------------------------------------------------- B dan C pada rekaman D4
def profile(ids, label):
    cv = collections.Counter()
    st = collections.Counter()
    ver = collections.Counter()
    n_aff = 0
    for c in ids:
        rec = json.load(open(d4[c]))
        cna = rec['containers'].get('cna', {})
        keys = {k for cont in [cna] + rec['containers'].get('adp', []) for m in cont.get('metrics', []) for k in m}
        v3, v4 = any(k.startswith('cvssV3') for k in keys), 'cvssV4_0' in keys
        cv['v3'] += v3
        cv['v4'] += v4
        cv['v4 saja'] += v4 and not v3
        cv['tanpa v3/v4'] += not (v3 or v4)
        for a in cna.get('affected', []):
            n_aff += 1
            st[a.get('defaultStatus', '(tidak ada)')] += 1
            for v in a.get('versions', []):
                ver['rentang' if (v.get('lessThan') or v.get('lessThanOrEqual')) else 'versi tunggal'] += 1
    n = len(ids)
    print(f"\n  [{label}] {n} rekaman")
    print("   CVSS:", ", ".join(f"{k} {pct(cv[k], n)}" for k in ('v3', 'v4', 'v4 saja', 'tanpa v3/v4')))
    print(f"   defaultStatus pada {n_aff} entri affected:", ", ".join(f"{k} {pct(v, n_aff)}" for k, v in st.most_common()))
    nv = sum(ver.values())
    print(f"   bentuk {nv} entri versi:", ", ".join(f"{k} {pct(v, nv)}" for k, v in ver.most_common()))

print("\n=== B/C. CVSS dan defaultStatus (rekaman CVE List v5)")
profile(sorted(c for c in cti if c in d4), 'CVE CTI yang ada di D4')
profile(sorted(d4), 'seluruh D4 (konteks)')
