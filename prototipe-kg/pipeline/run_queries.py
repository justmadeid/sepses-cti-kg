"""Langkah 4: jalankan kueri CQ untuk beberapa skenario waktu keputusan t.

Proposal: Subbab 4.5 (Tabel CQ dan jalur relasi), Subbab 4.6.2 (admissibility per t),
Subbab 4.7.2 (titik waktu t dan jendela W), hasil di Subbab 4.9.2 (Tabel status CQ).
Penjelasan: docs/02-panduan-kode.md "Langkah 4" dan docs/04-kueri-cq.md.

Pemakaian:
  .venv/bin/python -I pipeline/run_queries.py                       # baca output/kg-sampel-v0.1.trig (rdflib)
  .venv/bin/python -I pipeline/run_queries.py --endpoint http://localhost:3030/jejak/sparql
Keluaran:
  hasil/hasil-cq-v0.1.md   tabel hasil setiap kueri per skenario
"""
import argparse
import datetime as dt
import json
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
DEFAULT_T, DEFAULT_START, DEFAULT_DATE = "2025-09-30T23:59:59Z", "2025-04-03T00:00:00Z", '"2025-09-30"^^xsd:date'

# (label, t, W hari)
SCENARIOS = [("t = 30 Sep 2025, W = 180", "2025-09-30", 180),
             ("t = 31 Des 2025, W = 180", "2025-12-31", 180),
             ("t = 31 Des 2025, W = 90", "2025-12-31", 90)]
TIME_FREE = {"cq1-exposure-aset.rq", "cq2-keparahan.rq", "cq3-konteks-ancaman-naif.rq", "cq6-provenance.rq"}


def with_scenario(query, t, w):
    start = dt.date.fromisoformat(t) - dt.timedelta(days=w)
    return (query.replace(DEFAULT_T, f"{t}T23:59:59Z")
                 .replace(DEFAULT_START, f"{start}T00:00:00Z")
                 .replace(DEFAULT_DATE, f'"{t}"^^xsd:date'))


def run_local(query, ds):
    res = ds.query(query)
    cols = [str(v) for v in res.vars]
    return cols, [[("" if r[c] is None else str(r[c])) for c in cols] for r in res]


def run_endpoint(query, url):
    req = urllib.request.Request(url, data=urllib.parse.urlencode({"query": query}).encode(),
                                 headers={"Accept": "application/sparql-results+json"})
    data = json.load(urllib.request.urlopen(req))
    cols = data["head"]["vars"]
    return cols, [[b.get(c, {}).get("value", "") for c in cols] for b in data["results"]["bindings"]]


def md_table(cols, rows):
    if not rows:
        return "_(tidak ada hasil)_\n"
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        out.append("| " + " | ".join(v.replace("|", "\\|")[:140] for v in r) + " |")
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", help="URL SPARQL Fuseki; bila kosong, pakai rdflib in-memory")
    args = ap.parse_args()
    if args.endpoint:
        run = lambda q: run_endpoint(q, args.endpoint)
        source = f"endpoint {args.endpoint}"
    else:
        from rdflib import Dataset
        ds = Dataset(default_union=False)
        ds.parse(HERE / "output/kg-sampel-v0.1.trig", format="trig")
        run = lambda q: run_local(q, ds)
        source = "rdflib (output/kg-sampel-v0.1.trig)"

    lines = ["# Hasil kueri CQ, prototipe KG v0.1", "",
             f"Dihasilkan otomatis oleh `pipeline/run_queries.py` dari {source}. Jangan diedit manual.", ""]
    for path in sorted((HERE / "queries").glob("*.rq")):
        query = path.read_text()
        header = [l[2:] for l in query.splitlines() if l.startswith("# ")]
        lines += [f"## {path.name}", "", "> " + " ".join(h.strip() for h in header), ""]
        scenarios = [("tanpa waktu", None, None)] if path.name in TIME_FREE else SCENARIOS
        for label, t, w in scenarios:
            q = query if t is None else with_scenario(query, t, w)
            cols, rows = run(q)
            lines += [f"**Skenario: {label}** ({len(rows)} baris)", "", md_table(cols, rows)]
            print(f"{path.name:36s} {label:28s} {len(rows):3d} baris")
    (HERE / "hasil").mkdir(exist_ok=True)
    (HERE / "hasil/hasil-cq-v0.1.md").write_text("\n".join(lines))


if __name__ == "__main__":
    main()
