"""Langkah 1: ambil sampel STIX kecil dari ekspor OpenCTI (read-only terhadap data mentah).

Proposal: Subbab 4.9.2 (Prototipe KG v0.1), tahap 5 bagan alir Subbab 4.3
("pemetaan dimulai dari sampel kecil"). Penjelasan baris demi baris:
docs/02-panduan-kode.md bagian "Langkah 1".

Sampel = laporan OpenCTI yang menyebut CVE contoh, beserta objek yang dirujuk laporan
itu (object_refs). Indikator dan observable (file, url, domain, hostname) tidak dibawa
karena tidak dibutuhkan CQ1-CQ7 pada v0.1.

Pemakaian:
  .venv/bin/python -I pipeline/extract_sample.py <akar_proyek>
Keluaran:
  data/sampel-stix-v0.1.json   bundle STIX berisi objek sampel
  data/sampel-stix-v0.1.txt    ringkasan sampel
  data/cve-records/*.json      rekaman CVE List v5 untuk CVE di sampel (salinan apa adanya)
  data/kev-sampel.json         entri katalog CISA KEV untuk CVE di sampel
Sesudah langkah ini, langkah 2-5 tidak lagi membutuhkan data mentah.
"""
import collections
import glob
import hashlib
import json
import shutil
import sys
from pathlib import Path

SAMPLE_CVES = ["CVE-2025-8088", "CVE-2025-6218", "CVE-2025-64446"]
KEEP_TYPES = {"report", "intrusion-set", "malware", "attack-pattern", "vulnerability",
              "identity", "location", "relationship"}

root = Path(sys.argv[1])
out_dir = Path(__file__).resolve().parents[1] / "data"
files = sorted(glob.glob(str(root / "data/raw/alienvault/alienvault-split/alienvault-2025-*.json")))

objs = {}
for f in files:
    d = json.load(open(f))
    for o in (d["objects"] if isinstance(d, dict) else d):
        objs[o["id"]] = o

vuln_id = {o["name"]: i for i, o in objs.items() if o["type"] == "vulnerability"}
targets = {vuln_id[c] for c in SAMPLE_CVES}
reports = sorted((o for o in objs.values() if o["type"] == "report" and targets & set(o.get("object_refs", []))),
                 key=lambda r: r["published"])

keep = {}
for r in reports:
    keep[r["id"]] = r
    for ref in r["object_refs"]:
        o = objs[ref]
        if o["type"] in KEEP_TYPES - {"relationship"}:
            keep[ref] = o
for r in reports:
    for ref in r["object_refs"]:
        o = objs[ref]
        if o["type"] == "relationship" and o["source_ref"] in keep and o["target_ref"] in keep:
            keep[ref] = o
creators = {o.get("created_by_ref") for o in keep.values()} - {None}
for c in creators:
    keep[c] = objs[c]

bundle = {"type": "bundle", "id": "bundle--jejak-vp-sampel-v0-1", "objects": list(keep.values())}
out_dir.mkdir(exist_ok=True)
path = out_dir / "sampel-stix-v0.1.json"
path.write_text(json.dumps(bundle, indent=1, ensure_ascii=False))

# Salin rekaman CVE dan entri KEV yang dibutuhkan langkah 2, agar langkah 2-5 mandiri.
cve_dir = out_dir / "cve-records"
cve_dir.mkdir(exist_ok=True)
sample_cve_ids = sorted(o["name"] for o in keep.values() if o["type"] == "vulnerability")
copied = []
for cid in sample_cve_ids:
    y, n = cid.split("-")[1:]
    src = root / f"data/raw/cve-list-v5/{y}/{n[:-3]}xxx/{cid}.json"
    if src.exists():
        shutil.copyfile(src, cve_dir / f"{cid}.json")
        copied.append(cid)
kev_src = root / "data/raw/official-source-records/nvd-cisa-targeted-t1-v0.1/cisa-known-exploited-vulnerabilities.json"
kev_all = json.load(open(kev_src))
kev_subset = {k: kev_all.get(k) for k in ("title", "catalogVersion", "dateReleased")}
kev_subset["sourceSha256"] = hashlib.sha256(kev_src.read_bytes()).hexdigest()
kev_subset["vulnerabilities"] = [v for v in kev_all["vulnerabilities"] if v["cveID"] in sample_cve_ids]
(out_dir / "kev-sampel.json").write_text(json.dumps(kev_subset, indent=1))

lines = [f"Sumber: {len(files)} file alienvault-split; CVE contoh: {', '.join(SAMPLE_CVES)}",
         f"SHA-256 sampel: {hashlib.sha256(path.read_bytes()).hexdigest()}",
         f"Laporan: {len(reports)}"]
for r in reports:
    lines.append(f"  {r['published'][:10]}  {r['id']}  {r['name'][:80]}")
lines.append("Objek per tipe: " + json.dumps(collections.Counter(o["type"] for o in keep.values()), sort_keys=True))
lines.append(f"Rekaman CVE List v5 disalin: {len(copied)} dari {len(sample_cve_ids)} CVE di sampel")
lines.append(f"Entri KEV untuk CVE sampel: {len(kev_subset['vulnerabilities'])} (katalog {kev_subset['catalogVersion']})")
(out_dir / "sampel-stix-v0.1.txt").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
