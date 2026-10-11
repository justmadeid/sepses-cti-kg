"""KUANT-01 (read-only): ukur temuan prototipe KG v0.1 pada seluruh ekspor OpenCTI (D1).

  A. Atribut waktu relasi STIX: waktu kejadian atau waktu impor?
  B. Relasi yang dirujuk lebih dari satu laporan (dasar provenance per laporan, K3).
  C. Penerbit asli laporan di balik konektor agregator (dasar provenance dua tingkat, K15).
  D. Varian nama aktor/malware (beban entity linking).
  E. Indicator untuk CQ3b (kelayakan opsi B, K14).

Usage: python3 -I kuant01_opencti_prototype_findings.py <project_root>
"""
import collections
import glob
import json
import re
import statistics
import sys
from datetime import datetime
from urllib.parse import urlparse

root = sys.argv[1]
objs = {}
for f in sorted(glob.glob(root + '/data/raw/alienvault/alienvault-split/alienvault-2025-*.json')):
    d = json.load(open(f))
    for o in (d['objects'] if isinstance(d, dict) else d):
        objs[o['id']] = o

typ = lambda i: i.split('--')[0]
ts = lambda s: datetime.fromisoformat(s.replace('Z', '+00:00'))
pct = lambda a, b: f"{a}/{b} ({100 * a / b:.1f}%)" if b else f"{a}/0"
reports = [o for o in objs.values() if o['type'] == 'report']
rels = {i: o for i, o in objs.items() if o['type'] == 'relationship'}
reports_of = collections.defaultdict(list)
for r in reports:
    for x in r.get('object_refs', []):
        reports_of[x].append(r)
print(f"D1: {len(objs)} objek, {len(reports)} laporan, {len(rels)} relasi")

# ---------------------------------------------------------------- A. waktu relasi
print("\n=== A. Atribut waktu relasi STIX")
months = collections.Counter(o['created'][:7] for o in rels.values())
print("  created relasi per bulan (5 terbanyak):", months.most_common(5))
print("  created relasi di 2026:", pct(sum(1 for o in rels.values() if o['created'] >= '2026'), len(rels)))
pub = [r['published'] for r in reports]
print(f"  rentang published laporan: {min(pub)[:10]} .. {max(pub)[:10]}")
print("  laporan dengan created == published:", pct(sum(1 for r in reports if r.get('created') == r.get('published')), len(reports)))
in_rep = [i for i in rels if i in reports_of]
later = 0
for i in in_rep:
    first = min(ts(r['published']) for r in reports_of[i])
    if (ts(rels[i]['created']) - first).days > 30:
        later += 1
print("  relasi dalam laporan yang created-nya > 30 hari SESUDAH laporan pertama yang memuatnya:", pct(later, len(in_rep)))
for t in ('intrusion-set', 'malware', 'vulnerability', 'attack-pattern', 'indicator'):
    xs = [o for o in objs.values() if o['type'] == t]
    print(f"  {t:15s} created di 2026: {pct(sum(1 for o in xs if o['created'] >= '2026'), len(xs))}")

# ---------------------------------------------------------------- B. relasi multi-laporan
print("\n=== B. Relasi yang dirujuk lebih dari satu laporan")
def multi(ids, label):
    ids = [i for i in ids if i in reports_of]
    m = [i for i in ids if len(reports_of[i]) > 1]
    spans = [(max(ts(r['published']) for r in reports_of[i]) - min(ts(r['published']) for r in reports_of[i])).days for i in m]
    line = f"  {label:38s} dalam laporan {len(ids):7d}; >1 laporan {pct(len(m), len(ids))}"
    if spans:
        spans.sort()
        line += f"; selisih laporan pertama-terakhir: median {statistics.median(spans):.0f} hari, p90 {spans[int(0.9 * (len(spans) - 1))]} hari, maks {spans[-1]} hari"
    print(line)
multi(list(rels), 'semua relasi')
multi([i for i, o in rels.items() if o['relationship_type'] == 'targets' and typ(o['target_ref']) == 'vulnerability'], 'X targets CVE')
multi([i for i, o in rels.items() if o['relationship_type'] == 'targets' and typ(o['target_ref']) in ('identity', 'location')], 'X targets sektor/lokasi')
multi([i for i, o in rels.items() if o['relationship_type'] == 'indicates'], 'indicator indicates X')
cnt = collections.Counter(len(reports_of[i]) for i in rels if i in reports_of)
print("  sebaran jumlah laporan per relasi:", sorted(cnt.items())[:8], "...")

# ---------------------------------------------------------------- C. penerbit asli
print("\n=== C. Penerbit asli di balik konektor")
creators = collections.Counter(objs.get(r.get('created_by_ref'), {}).get('name', '?') for r in reports)
print("  pembuat laporan (created_by_ref):", creators.most_common())
dom = collections.Counter()
with_src = 0
for r in reports:
    ds = set()
    for x in r.get('external_references', []):
        host = urlparse(x.get('url', '')).netloc.lower().removeprefix('www.')
        if host and 'otx.alienvault.com' not in host:
            ds.add(host)
    with_src += bool(ds)
    dom.update(ds)
print("  laporan dengan >=1 URL sumber asli (selain OTX):", pct(with_src, len(reports)))
print("  jumlah domain sumber asli berbeda:", len(dom))
print("  15 domain terbanyak:", dom.most_common(15))

# ---------------------------------------------------------------- D. varian nama
print("\n=== D. Varian nama aktor/malware (heuristik)")
STOP = {'group', 'apt', 'team', 'the', 'gang', 'actor', 'actors', 'threat', 'division', 'campaign', 'malware', 'ransomware', 'backdoor', 'loader', 'stealer', 'rat', 'variant', 'agent'}
def tokens(n):
    return [t for t in re.split(r'[^a-z0-9]+', n.lower()) if t]
def analyze(t):
    names = sorted({o['name'] for o in objs.values() if o['type'] == t})
    composite = [n for n in names if ',' in n or ' & ' in n or ' and ' in n.lower()]
    parent = {n: n for n in names}
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    core = {n: frozenset(tokens(n)) - STOP for n in names}
    # Aturan ketat: nama A dianggap varian dari nama B bila semua token inti A (>= 1 token,
    # panjang total >= 4 huruf) termuat dalam token inti B, misalnya "RomCom" dalam
    # "RomCom, Paper Werewolf" atau "LockBit" dalam "LockBit 3.0".
    for a in names:
        if not core[a] or sum(map(len, core[a])) < 4:
            continue
        for b in names:
            if a != b and core[a] < core[b]:
                parent[find(b)] = find(a)
    clusters = collections.defaultdict(list)
    for n in names:
        clusters[find(n)].append(n)
    multi_c = sorted((c for c in clusters.values() if len(c) > 1), key=len, reverse=True)
    with_ext = sum(1 for o in objs.values() if o['type'] == t and any(e.get('external_id') for e in o.get('external_references', [])))
    n_obj = sum(1 for o in objs.values() if o['type'] == t)
    print(f"  {t}: {len(names)} nama unik; nama gabungan (koma/&): {pct(len(composite), len(names))}; "
          f"dengan external_id: {pct(with_ext, n_obj)}")
    print(f"    klaster varian (nama satu termuat penuh di nama lain; indikatif, perlu cek manual): {len(multi_c)} klaster, {sum(map(len, multi_c))} nama")
    for c in multi_c[:6]:
        print("     -", c[:6])
analyze('intrusion-set')
analyze('malware')

# ---------------------------------------------------------------- E. indicator untuk CQ3b
print("\n=== E. Indicator (opsi B, CQ3b)")
inds = [o for o in objs.values() if o['type'] == 'indicator']
print("  indicator:", len(inds), "| dengan valid_until:", pct(sum(1 for o in inds if o.get('valid_until')), len(inds)),
      "| revoked:", pct(sum(1 for o in inds if o.get('revoked')), len(inds)))
targets_cve = collections.defaultdict(set)  # actor/malware -> CVE
for o in rels.values():
    if o['relationship_type'] == 'targets' and typ(o['target_ref']) == 'vulnerability' and typ(o['source_ref']) in ('malware', 'intrusion-set'):
        targets_cve[o['source_ref']].add(o['target_ref'])
ind_to = collections.defaultdict(set)
for o in rels.values():
    if o['relationship_type'] == 'indicates' and typ(o['target_ref']) in ('malware', 'intrusion-set'):
        ind_to[o['source_ref']].add(o['target_ref'])
cves = {i for i, o in objs.items() if o['type'] == 'vulnerability'}
cve_ind = collections.defaultdict(set)
for ind, srcs in ind_to.items():
    for s in srcs:
        for c in targets_cve.get(s, ()):
            cve_ind[c].add(ind)
print("  CVE yang punya >=1 indicator lewat indicator->{malware,aktor}->CVE (global):", pct(len(cve_ind), len(cves)))
# versi per laporan: indicator, kedua relasi, dan CVE ada dalam laporan yang sama
cve_ind_rep = collections.defaultdict(set)
for r in reports:
    refs = set(r.get('object_refs', []))
    t_rel = [rels[x] for x in refs if x in rels and rels[x]['relationship_type'] == 'targets' and typ(rels[x]['target_ref']) == 'vulnerability' and typ(rels[x]['source_ref']) in ('malware', 'intrusion-set')]
    i_rel = [rels[x] for x in refs if x in rels and rels[x]['relationship_type'] == 'indicates' and typ(rels[x]['target_ref']) in ('malware', 'intrusion-set')]
    by_src = collections.defaultdict(set)
    for o in i_rel:
        by_src[o['target_ref']].add(o['source_ref'])
    for o in t_rel:
        cve_ind_rep[o['target_ref']] |= by_src.get(o['source_ref'], set())
cve_ind_rep = {c: v for c, v in cve_ind_rep.items() if v}
print("  CVE yang punya >=1 indicator dalam LAPORAN YANG SAMA:", pct(len(cve_ind_rep), len(cves)))
for t in ('2025-09-30T23:59:59+00:00', '2025-12-31T23:59:59+00:00'):
    T = ts(t)
    def valid(i):
        o = objs[i]
        vf, vu = o.get('valid_from'), o.get('valid_until')
        return (not o.get('revoked')) and (not vf or ts(vf) <= T) and (not vu or T < ts(vu))
    def valid_norev(i):
        o = objs[i]
        vf, vu = o.get('valid_from'), o.get('valid_until')
        return (not vf or ts(vf) <= T) and (not vu or T < ts(vu))
    n = sum(1 for c, v in cve_ind_rep.items() if any(valid(i) for i in v))
    n2 = sum(1 for c, v in cve_ind_rep.items() if any(valid_norev(i) for i in v))
    print(f"  t = {t[:10]}: CVE dengan >=1 indicator berlaku (laporan sama; valid_from<=t<valid_until): "
          f"tanpa syarat revoked {pct(n2, len(cves))}; dengan revoked snapshot 2026 {pct(n, len(cves))}")
print("  Catatan: status revoked adalah keadaan snapshot (2026), bukan keadaan per t; memakainya untuk t 2025"
      " termasuk bocor dari masa depan kecuali riwayat versi tersedia.")
