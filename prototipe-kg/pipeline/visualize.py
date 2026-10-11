"""Langkah 5: visualisasi A-box (HTML interaktif) langsung dari KG.

Proposal: tahap 5 bagan alir Subbab 4.3 ("hasil pemetaan divisualisasikan sebagai graf")
dan Gambar A-box Subbab 4.5.1. Penjelasan: docs/02-panduan-kode.md "Langkah 5".

Graf yang digambar: aset -> exposure -> CVE -> CWE/CVSS/KEV, laporan yang menyebut CVE,
aktor/malware yang menargetkan CVE menurut laporan itu, dan sektor yang disebut laporan.
Pilihan waktu keputusan t dan jendela W menyembunyikan laporan (beserta relasinya)
yang belum terbit atau sudah usang pada t.

Pemakaian:
  .venv/bin/python -I pipeline/visualize.py
Keluaran:
  hasil/visualisasi-abox-v0.1.html   (butuh internet untuk memuat vis-network dari CDN)
"""
import json
from pathlib import Path

from rdflib import Dataset

HERE = Path(__file__).resolve().parents[1]
ds = Dataset(default_union=False)
ds.parse(HERE / "output/kg-sampel-v0.1.trig", format="trig")

PREFIX = """
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX dcterm: <http://purl.org/dc/terms/>
PREFIX cve: <http://w3id.org/sepses/vocab/ref/cve#>
PREFIX cvss: <http://w3id.org/sepses/vocab/ref/cvss#>
PREFIX cat: <http://w3id.org/sepses/vocab/ref/attack#>
PREFIX ext: <http://example.org/jejak-vp/ext#>
PREFIX g: <http://example.org/jejak-vp/graph/>
"""
nodes, edges = {}, []


def node(key, label, group, title=""):
    nodes.setdefault(key, {"id": key, "label": label, "group": group, "title": title or label})


def edge(a, b, label, date=None, dashes=False):
    edges.append({"from": a, "to": b, "label": label, "date": date, "dashes": dashes})


# Aset, organisasi, exposure
for r in ds.query(PREFIX + """
SELECT ?a ?al ?c ?id ?st ?basis ?org ?orgl ?sek ?sekl WHERE {
  GRAPH g:assets { ?a a ext:Asset ; rdfs:label ?al ; ext:ownedBy ?org . ?org rdfs:label ?orgl ; ext:inSector ?sek . }
  GRAPH g:derived-exposure { ?e ext:assessedAsset ?a ; ext:assessedCVE ?c ; ext:exposureStatus ?st ; ext:matchBasis ?basis . }
  GRAPH g:cve-sepses { ?c dcterm:identifier ?id . }
  OPTIONAL { GRAPH g:opencti-entities { ?sek rdfs:label ?sekl } }
}"""):
    a = str(r.a)
    node(a, str(r.al).split(" (")[0], "aset", str(r.al))
    node(str(r.org), str(r.orgl), "organisasi")
    edge(a, str(r.org), "ownedBy")
    node(str(r.sek), str(r.sekl or "Government"), "sektor")
    edge(str(r.org), str(r.sek), "inSector")
    node(str(r.c), str(r.id), "cve")
    edge(a, str(r.c), f"exposure {r.st}", dashes=str(r.st) != "TRUE")
    nodes[a]["title"] += f"\n{r.id}: {r.st} - {r.basis}"

cves = [k for k, v in nodes.items() if v["group"] == "cve"]
values = " ".join(f"<{c}>" for c in cves)

# Keparahan dan KEV
for r in ds.query(PREFIX + f"""
SELECT ?c ?cwe ?s3 ?s4 ?kev WHERE {{
  VALUES ?c {{ {values} }}
  GRAPH g:cve-sepses {{ OPTIONAL {{ ?c cve:hasCWE ?cwe }} OPTIONAL {{ ?c cve:hasCVSS3BaseMetric/cvss:baseScore ?s3 }}
                       OPTIONAL {{ ?c ext:cvssV4BaseScore ?s4 }} }}
  OPTIONAL {{ GRAPH g:kev {{ ?c ext:kevDateAdded ?kev }} }}
}}"""):
    c = str(r.c)
    if r.cwe:
        node(str(r.cwe), str(r.cwe).rsplit("/", 1)[-1], "cwe")
        edge(c, str(r.cwe), "hasCWE")
    score = f"CVSS v3 {r.s3}" if r.s3 else (f"CVSS v4 {r.s4}" if r.s4 else None)
    if score:
        node(c + "#cvss", score, "cvss")
        edge(c, c + "#cvss", "hasCVSS")
    if r.kev:
        node(c + "#kev", f"KEV sejak {r.kev}", "kev")
        edge(c, c + "#kev", "kevDateAdded", date=str(r.kev) + "T00:00:00")

# Laporan, aktor/malware yang menargetkan CVE, sektor yang disebut laporan
for r in ds.query(PREFIX + f"""
SELECT DISTINCT ?lap ?judul ?terbit ?c ?x ?xl ?kelas WHERE {{
  VALUES ?c {{ {values} }}
  GRAPH ?lap {{ ?lap ext:mentions ?c . OPTIONAL {{ ?r cat:hasTargetRef ?c ; cat:relationshipType "targets" ; cat:hasSourceRef ?x . }} }}
  GRAPH g:report-metadata {{ ?lap dcterm:title ?judul ; ext:published ?terbit . }}
  OPTIONAL {{ GRAPH g:opencti-entities {{ ?x a ?kelas ; rdfs:label ?xl . }} }}
}}"""):
    lap, date = str(r.lap), str(r.terbit)[:19]
    node(lap, f"Laporan {date[:10]}", "laporan", f"{r.judul}\nterbit {date[:10]}")
    nodes[lap]["date"] = date
    edge(lap, str(r.c), "mentions", date=date)
    if r.x is not None and r.kelas is not None and str(r.kelas).endswith(("intrusion-set", "malware")):
        grp = "aktor" if str(r.kelas).endswith("intrusion-set") else "malware"
        node(str(r.x), str(r.xl), grp)
        edge(str(r.x), str(r.c), f"targets ({date[:10]})", date=date)
        edge(lap, str(r.x), "mentions", date=date, dashes=True)
for r in ds.query(PREFIX + f"""
SELECT DISTINCT ?lap ?s ?sl ?terbit WHERE {{
  VALUES ?c {{ {values} }}
  GRAPH ?lap {{ ?lap ext:mentions ?c , ?s . }}
  GRAPH g:opencti-entities {{ ?s a ext:Sector ; rdfs:label ?sl . }}
  GRAPH g:report-metadata {{ ?lap ext:published ?terbit . }}
}}"""):
    node(str(r.s), str(r.sl), "sektor")
    edge(str(r.lap), str(r.s), "mentions", date=str(r.terbit)[:19], dashes=True)

seen = {}
for e in edges:
    seen.setdefault((e["from"], e["to"], e["label"]), e)
edges = list(seen.values())
for i, e in enumerate(edges):
    e["id"] = i
data = json.dumps({"nodes": list(nodes.values()), "edges": edges}, ensure_ascii=False)
html = (HERE / "pipeline/visualisasi-template.html").read_text().replace("__DATA__", data)
(HERE / "hasil/visualisasi-abox-v0.1.html").write_text(html)
print(f"{len(nodes)} simpul, {len(edges)} sisi -> hasil/visualisasi-abox-v0.1.html")
