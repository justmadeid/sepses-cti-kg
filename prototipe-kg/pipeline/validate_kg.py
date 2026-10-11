"""Langkah 3: validasi KG dengan SHACL (pyshacl).

Proposal: Subbab 3.7 (teori SHACL) dan Subbab 4.4.1 (validasi ontologi dan data).
Penjelasan: docs/02-panduan-kode.md "Langkah 3".

Semua graf A-box digabung (union) lalu divalidasi terhadap shapes/shapes-v0.1.ttl.
Pemakaian:
  .venv/bin/python -I pipeline/validate_kg.py
Keluaran:
  output/laporan-shacl-v0.1.txt
"""
import collections
from pathlib import Path

from pyshacl import validate
from rdflib import Dataset, Graph, Namespace
from rdflib.namespace import RDF

HERE = Path(__file__).resolve().parents[1]
SH = Namespace("http://www.w3.org/ns/shacl#")
TBOX = "http://example.org/jejak-vp/graph/tbox"

ds = Dataset(default_union=False)
ds.parse(HERE / "output/kg-sampel-v0.1.trig", format="trig")
data = Graph()
for g in ds.graphs():
    if str(g.identifier) != TBOX:
        data += g
shapes = Graph().parse(HERE / "shapes/shapes-v0.1.ttl")

conforms, report, _ = validate(data, shacl_graph=shapes, inference="none", allow_warnings=True)

counts = collections.Counter()
details = collections.defaultdict(list)
for r in report.subjects(RDF.type, SH.ValidationResult):
    sev = report.value(r, SH.resultSeverity).split("#")[1]
    msg = str(report.value(r, SH.resultMessage))
    counts[(sev, msg)] += 1
    details[(sev, msg)].append(str(report.value(r, SH.focusNode)).rsplit("/", 1)[-1])

lines = [f"Triple divalidasi (tanpa T-box): {len(data)}",
         f"Conforms (tanpa Violation): {conforms}",
         "Ringkasan hasil:"]
if not counts:
    lines.append("  tidak ada pelanggaran")
for (sev, msg), n in sorted(counts.items()):
    lines.append(f"  [{sev}] x{n}: {msg}")
    lines.append(f"      fokus: {', '.join(sorted(details[(sev, msg)])[:12])}")
(HERE / "output/laporan-shacl-v0.1.txt").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
