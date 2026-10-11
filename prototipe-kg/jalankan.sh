#!/usr/bin/env bash
# Menjalankan seluruh alur prototipe KG v0.1 dari awal.
#   ./jalankan.sh            rdflib saja (tanpa Docker)
#   ./jalankan.sh --fuseki   juga memuat KG ke Fuseki lokal dan menjalankan kueri di sana
set -euo pipefail
cd "$(dirname "$0")"
# Akar data mentah (ekspor OpenCTI, CVE List v5, KEV). Hanya dibutuhkan langkah 1.
ROOT="${JEJAK_DATA_ROOT:-$(cd ../.. && pwd)}"
PY=.venv/bin/python
[ -x "$PY" ] || { python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt; }

if [ -d "$ROOT/data/raw/alienvault/alienvault-split" ]; then
  $PY -I pipeline/extract_sample.py "$ROOT"   # 1. sampel STIX + rekaman CVE/KEV dari data mentah
else
  echo "Data mentah tidak ditemukan di $ROOT; langkah 1 dilewati, memakai data/ yang sudah ada."
fi
$PY -I pipeline/build_kg.py                   # 2. pemetaan ke RDF (TriG, graf bernama)
$PY -I pipeline/validate_kg.py                # 3. validasi SHACL
$PY -I pipeline/run_queries.py                # 4. kueri CQ (rdflib)
$PY -I pipeline/visualize.py                  # 5. visualisasi A-box

if [ "${1:-}" = "--fuseki" ]; then
  (cd fuseki && docker compose up -d --build)
  until curl -sf http://localhost:3030/\$/ping >/dev/null; do sleep 2; done
  curl -sf -X PUT --data-binary @output/kg-sampel-v0.1.trig -H 'Content-Type: application/trig' \
       http://localhost:3030/jejak/data
  $PY -I pipeline/run_queries.py --endpoint http://localhost:3030/jejak/sparql
  echo "Fuseki: http://localhost:3030  (dataset /jejak)"
fi
