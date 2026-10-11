"""Langkah 2: pemetaan sampel ke RDF (A-box) dalam satu file TriG.

Proposal: Subbab 4.4 (rancangan ontologi dan integrasi: reuse kosakata 4.4.1,
pemetaan 4.4.2, entity linking 4.4.3, provenance per laporan 4.4.4) dan Subbab 4.6.1
(exposure aset, logika tiga nilai). Penjelasan: docs/02-panduan-kode.md "Langkah 2".

Masukan (semuanya hasil langkah 1 atau file tetap di folder ini):
  data/sampel-stix-v0.1.json      sampel OpenCTI/STIX 2.1
  data/cve-records/*.json         rekaman CVE List v5 (pengganti sementara SEPSES;
                                  endpoint SEPSES tidak merespons sejak 9 Okt 2026)
  data/kev-sampel.json            entri CISA KEV untuk CVE di sampel
  data/aset-skenario.csv, data/organisasi-skenario.csv   inventaris skenario
  ontology/tbox-v0.1.ttl

Pemakaian:
  .venv/bin/python -I pipeline/build_kg.py
Keluaran:
  output/kg-sampel-v0.1.trig    semua graf bernama (T-box + A-box)
  output/statistik-kg-v0.1.txt  jumlah triple per graf
"""
import csv
import json
import re
from pathlib import Path

from rdflib import Dataset, Literal, Namespace, URIRef
from rdflib.namespace import DCTERMS, PROV, RDF, RDFS, XSD

HERE = Path(__file__).resolve().parents[1]

CVE = Namespace("http://w3id.org/sepses/vocab/ref/cve#")
CVSS = Namespace("http://w3id.org/sepses/vocab/ref/cvss#")
CAT = Namespace("http://w3id.org/sepses/vocab/ref/attack#")
EXT = Namespace("http://example.org/jejak-vp/ext#")
SEPSES_RES = "http://w3id.org/sepses/resource/"
RES = Namespace("http://example.org/jejak-vp/resource/")
GRAPH = Namespace("http://example.org/jejak-vp/graph/")

G_TBOX, G_ENT, G_REPMETA = GRAPH["tbox"], GRAPH["opencti-entities"], GRAPH["report-metadata"]
G_CVE, G_KEV, G_ASSET, G_EXPO = GRAPH["cve-sepses"], GRAPH["kev"], GRAPH["assets"], GRAPH["derived-exposure"]

ds = Dataset()
for p, ns in [("cve", CVE), ("cvss", CVSS), ("cat", CAT), ("ext", EXT), ("res", RES), ("g", GRAPH),
              ("prov", PROV), ("dcterm", DCTERMS), ("cwe", "http://w3id.org/sepses/vocab/ref/cwe#"),
              ("cveres", SEPSES_RES + "cve/"), ("cweres", SEPSES_RES + "cwe/")]:
    ds.bind(p, ns)

ds.graph(G_TBOX).parse(HERE / "ontology/tbox-v0.1.ttl")
ent, repmeta, gcve, gkev, gasset, gexpo = (ds.graph(g) for g in (G_ENT, G_REPMETA, G_CVE, G_KEV, G_ASSET, G_EXPO))


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def cve_iri(cve_id):
    return URIRef(SEPSES_RES + "cve/" + cve_id)


# ---------------------------------------------------------------- OpenCTI / STIX
bundle = json.load(open(HERE / "data/sampel-stix-v0.1.json"))["objects"]
objs = {o["id"]: o for o in bundle}
iri = {}  # STIX id -> IRI
for o in bundle:
    t = o["type"]
    if t == "vulnerability":
        # Entity linking STIX -> SEPSES: nama objek vulnerability adalah ID CVE (cocok persis).
        iri[o["id"]] = cve_iri(o["name"])
    elif t == "identity" and o.get("identity_class") == "class":
        iri[o["id"]] = RES["sector/" + slug(o["name"])]
    elif t == "location" and o.get("x_opencti_location_type") == "Country":
        iri[o["id"]] = RES["country/" + slug(o["name"])]
    elif t == "identity":
        iri[o["id"]] = RES["agent/" + slug(o["name"])]
    elif t == "report":
        iri[o["id"]] = RES["report/" + o["id"].split("--")[1]]
    else:
        iri[o["id"]] = RES["stix/" + o["id"]]

for o in bundle:
    s, t = iri[o["id"]], o["type"]
    if t in ("intrusion-set", "malware", "attack-pattern"):
        ent.add((s, RDF.type, CAT[t]))
        ent.add((s, RDFS.label, Literal(o["name"])))
        ent.add((s, EXT.stixId, Literal(o["id"])))
        if t == "attack-pattern" and o.get("x_mitre_id"):
            ent.add((s, DCTERMS.identifier, Literal(o["x_mitre_id"])))
    elif t == "vulnerability":
        ent.add((s, RDF.type, CVE.CVE))
        ent.add((s, EXT.stixId, Literal(o["id"])))
    elif t == "identity" and o.get("identity_class") == "class":
        ent.add((s, RDF.type, EXT.Sector))
        ent.add((s, RDFS.label, Literal(o["name"])))
    elif t == "location":
        ent.add((s, RDF.type, EXT.Country))
        ent.add((s, RDFS.label, Literal(o["name"])))
    elif t == "identity":
        repmeta.add((s, RDF.type, PROV.Agent))
        repmeta.add((s, RDFS.label, Literal(o["name"])))

reports = [o for o in bundle if o["type"] == "report"]
for r in reports:
    rep = iri[r["id"]]
    repmeta.add((rep, RDF.type, EXT.Report))
    repmeta.add((rep, DCTERMS.title, Literal(r["name"])))
    repmeta.add((rep, EXT.published, Literal(r["published"].replace("Z", "+00:00"), datatype=XSD.dateTime)))
    repmeta.add((rep, EXT.stixId, Literal(r["id"])))
    repmeta.add((rep, PROV.wasAttributedTo, iri[r["created_by_ref"]]))
    for x in r.get("external_references", []):
        if x.get("url"):
            repmeta.add((rep, EXT.sourceUrl, Literal(x["url"], datatype=XSD.anyURI)))
    # Isi laporan: satu graf bernama per laporan, nama graf = IRI laporan.
    g = ds.graph(rep)
    for ref in r["object_refs"]:
        if ref not in objs:
            continue
        o = objs[ref]
        if o["type"] == "relationship":
            rel = RES["stix/" + ref]
            g.add((rel, RDF.type, CAT.relationship))
            g.add((rel, CAT.hasSourceRef, iri[o["source_ref"]]))
            g.add((rel, CAT.hasTargetRef, iri[o["target_ref"]]))
            g.add((rel, CAT.relationshipType, Literal(o["relationship_type"])))
        else:
            g.add((rep, EXT.mentions, iri[ref]))

# ---------------------------------------------------------------- CVE List v5 (pengganti SEPSES)
sample_cves = sorted(o["name"] for o in bundle if o["type"] == "vulnerability")
missing_cve = []
for cid in sample_cves:
    path = HERE / f"data/cve-records/{cid}.json"
    if not path.exists():
        missing_cve.append(cid)
        continue
    rec = json.load(open(path))
    cna = rec["containers"]["cna"]
    s = cve_iri(cid)
    gcve.add((s, RDF.type, CVE.CVE))
    gcve.add((s, DCTERMS.identifier, Literal(cid)))
    if rec["cveMetadata"].get("datePublished"):
        gcve.add((s, DCTERMS.issued, Literal(rec["cveMetadata"]["datePublished"][:10], datatype=XSD.date)))
    for pt in cna.get("problemTypes", []):
        for d in pt.get("descriptions", []):
            if d.get("cweId"):
                gcve.add((s, CVE.hasCWE, URIRef(SEPSES_RES + "cwe/" + d["cweId"])))
    for cont in [cna] + rec["containers"].get("adp", []):
        for m in cont.get("metrics", []):
            for key, v in m.items():
                if key.startswith("cvssV3"):
                    node = URIRef(SEPSES_RES + "cvss/CVSS3BaseMetric/" + cid)
                    gcve.add((s, CVE.hasCVSS3BaseMetric, node))
                    gcve.add((node, RDF.type, CVSS.CVSS3BaseMetric))
                    gcve.add((node, CVSS.baseScore, Literal(v["baseScore"], datatype=XSD.decimal)))
                    gcve.add((node, CVSS.baseSeverity, Literal(v["baseSeverity"])))
                    gcve.add((node, CVSS.vectorString, Literal(v["vectorString"])))
                elif key == "cvssV4_0":
                    gcve.add((s, EXT.cvssV4BaseScore, Literal(v["baseScore"], datatype=XSD.decimal)))
    for i, a in enumerate(cna.get("affected", [])):
        ap = RES[f"affected/{cid}/{i}"]
        gcve.add((s, EXT.hasAffectedProduct, ap))
        gcve.add((ap, RDF.type, EXT.AffectedProduct))
        for k in ("vendor", "product", "defaultStatus"):
            if a.get(k):
                gcve.add((ap, EXT[k], Literal(a[k])))
        for cpe in a.get("cpes", []):
            gcve.add((ap, EXT.cpe23, Literal(cpe)))
        for j, v in enumerate(a.get("versions", [])):
            vr = RES[f"affected/{cid}/{i}/v{j}"]
            gcve.add((ap, EXT.hasVersionRange, vr))
            gcve.add((vr, EXT.status, Literal(v.get("status", ""))))
            if v.get("lessThanOrEqual"):
                gcve.add((vr, EXT.versionStart, Literal(v["version"])))
                gcve.add((vr, EXT.versionEndIncluding, Literal(v["lessThanOrEqual"])))
            elif v.get("lessThan"):
                gcve.add((vr, EXT.versionStart, Literal(v["version"])))
                gcve.add((vr, EXT.versionEndExcluding, Literal(v["lessThan"])))
            else:
                gcve.add((vr, EXT.versionExact, Literal(v["version"])))

# ---------------------------------------------------------------- CISA KEV
kev_path = HERE / "data/kev-sampel.json"
kev = {v["cveID"]: v for v in json.load(open(kev_path))["vulnerabilities"]}
for cid in sample_cves:
    if cid in kev:
        s = cve_iri(cid)
        gkev.add((s, EXT.kevDateAdded, Literal(kev[cid]["dateAdded"], datatype=XSD.date)))
        gkev.add((s, EXT.kevRansomwareUse, Literal(kev[cid]["knownRansomwareCampaignUse"])))

# ---------------------------------------------------------------- aset skenario
for row in csv.DictReader(open(HERE / "data/organisasi-skenario.csv")):
    org = RES["org/" + slug(row["org_id"])]
    gasset.add((org, RDF.type, EXT.Organization))
    gasset.add((org, RDFS.label, Literal(row["label"])))
    # Sektor/negara organisasi ditautkan ke IRI yang sama dengan sektor/negara OpenCTI (cocok nama).
    gasset.add((org, EXT.inSector, RES["sector/" + slug(row["sector"])]))
    gasset.add((org, EXT.inCountry, RES["country/" + slug(row["country"])]))
assets = list(csv.DictReader(open(HERE / "data/aset-skenario.csv")))
for row in assets:
    a = RES["asset/" + slug(row["asset_id"])]
    gasset.add((a, RDF.type, EXT.Asset))
    gasset.add((a, RDFS.label, Literal(f"{row['asset_id']} ({row['label']})")))
    gasset.add((a, EXT.vendor, Literal(row["vendor"])))
    gasset.add((a, EXT.product, Literal(row["product"])))
    gasset.add((a, EXT.installedVersion, Literal(row["installed_version"])))
    gasset.add((a, EXT.ownedBy, RES["org/pemda-x"]))


# ---------------------------------------------------------------- exposure (diturunkan)
def vtuple(v):
    """'7.11 (64-bit)' -> (7, 11); bagian non-angka di belakang diabaikan."""
    m = re.match(r"\s*(\d+(?:\.\d+)*)", v or "")
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def norm(text):
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


STATUS = {"affected": "TRUE", "unaffected": "FALSE"}
activity = RES["activity/exposure-matching-v0.1"]
gexpo.add((activity, RDF.type, PROV.Activity))
gexpo.add((activity, RDFS.comment, Literal(
    "Pencocokan nama produk (dinormalisasi) lalu rentang versi CVE List v5; "
    "versi di luar daftar memakai defaultStatus. Vendor tidak dipakai karena berbeda "
    "antar sumber (mis. 'win.rar GmbH' vs 'RARLAB').", lang="id")))
for cid in sample_cves:
    path = HERE / f"data/cve-records/{cid}.json"
    if not path.exists():
        continue
    cna = json.load(open(path))["containers"]["cna"]
    for row in assets:
        for a in cna.get("affected", []):
            if norm(a.get("product")) != norm(row["product"]):
                continue
            v = vtuple(row["installed_version"])
            status, basis = None, None
            for e in a.get("versions", []):
                end = e.get("lessThanOrEqual") or e.get("lessThan")
                if end:
                    lo, hi = vtuple(e["version"]), vtuple(end)
                    inside = lo <= v <= hi if e.get("lessThanOrEqual") else lo <= v < hi
                    if inside:
                        status = STATUS.get(e["status"], "UNKNOWN")
                        op = "<=" if e.get("lessThanOrEqual") else "<"
                        basis = f"versi {row['installed_version']} di dalam rentang {e['version']} .. {op} {end} ({e['status']})"
                        break
                elif vtuple(e["version"]) == v:
                    status = STATUS.get(e["status"], "UNKNOWN")
                    basis = f"versi {row['installed_version']} sama dengan versi tercatat '{e['version']}' ({e['status']})"
                    break
            if status is None:
                ds_ = a.get("defaultStatus", "unknown")
                status = STATUS.get(ds_, "UNKNOWN")
                basis = f"versi {row['installed_version']} tidak tercantum; defaultStatus = {ds_}"
            ea = RES[f"exposure/{slug(row['asset_id'])}/{cid}"]
            gexpo.add((ea, RDF.type, EXT.ExposureAssessment))
            gexpo.add((ea, EXT.assessedAsset, RES["asset/" + slug(row["asset_id"])]))
            gexpo.add((ea, EXT.assessedCVE, cve_iri(cid)))
            gexpo.add((ea, EXT.exposureStatus, Literal(status)))
            gexpo.add((ea, EXT.matchBasis, Literal(f"produk '{a.get('vendor')} {a.get('product')}': {basis}", lang="id")))
            gexpo.add((ea, PROV.wasGeneratedBy, activity))


def write_trig_sorted(dataset, path):
    """Tulis TriG dengan graf diurutkan menurut IRI agar keluaran sama di setiap run (diff Git bersih)."""
    prefixes = sorted(dataset.namespaces(), key=lambda kv: kv[0])
    parts = [f"@prefix {p}: <{ns}> ." for p, ns in prefixes] + [""]
    for g in sorted(dataset.graphs(), key=lambda g: str(g.identifier)):
        if len(g) == 0:
            continue
        body = g.serialize(format="turtle")
        body = "\n".join("    " + l if l else l for l in body.splitlines() if not l.startswith("@prefix"))
        parts.append(f"<{g.identifier}> {{\n{body.strip(chr(10))}\n}}\n")
    path.write_text("\n".join(parts))


# ---------------------------------------------------------------- simpan
out = HERE / "output"
out.mkdir(exist_ok=True)
write_trig_sorted(ds, out / "kg-sampel-v0.1.trig")
lines = ["Graf bernama dan jumlah triple:"]
total = 0
for g in sorted(ds.graphs(), key=lambda g: str(g.identifier)):
    if len(g) == 0:
        continue
    total += len(g)
    lines.append(f"  {len(g):6d}  {g.identifier}")
lines.append(f"  {total:6d}  TOTAL")
lines.append(f"CVE di sampel: {len(sample_cves)}; tanpa rekaman CVE List v5: {missing_cve or '-'}")
lines.append(f"CVE berstatus KEV (kapan pun): {sum(1 for c in sample_cves if c in kev)}")
(out / "statistik-kg-v0.1.txt").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
