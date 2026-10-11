# Peta Proposal ↔ Kode

Nomor subbab, tabel, dan gambar merujuk ke draft proposal `v3-draft-13` (atau sesudahnya)
di [`../proposal/`](../proposal/). Arah sebaliknya (proposal menunjuk ke kode) ada di
Lampiran D proposal.

## A. Alur bercerita: menjelaskan proposal sambil menunjukkan kode

Urutan ini dipakai saat presentasi atau bimbingan. Setiap langkah: apa yang dikatakan
proposal, lalu bukti di repositori.

| No. | Cerita | Proposal | Tunjukkan di repositori |
|---|---|---|---|
| 1 | **Masalahnya nyata dan terukur.** Konteks ancaman tersedia luas, tetapi hampir separuhnya bocor dari masa depan atau usang bila waktu diabaikan. | Subbab 1.1–1.2, Tabel 1.1 | [`data-checks/stale_context_profile.out.txt`](../data-checks/stale_context_profile.out.txt), [`data-checks/threat_context_profile.out.txt`](../data-checks/threat_context_profile.out.txt) |
| 2 | **Dari mana datanya.** OpenCTI di Docker dengan konektor AlienVault OTX, lalu diekspor ke STIX 2.1. | Subbab 4.2.2, Gambar 4.2, Tabel 4.2 | [`infrastruktur/opencti/`](../infrastruktur/opencti/), [`docs/01-alur-data.md`](01-alur-data.md) |
| 3 | **Mulai dari CQ.** KG dibangun untuk menjawab pertanyaan konkret. | Subbab 4.5, Tabel 4.5 | [`prototipe-kg/queries/`](../prototipe-kg/queries/) (satu file per CQ) |
| 4 | **Dari CQ ke T-box.** Kelas dan relasi memakai ulang SEPSES/ICS-SEC; istilah baru hanya bila dibutuhkan CQ. | Subbab 4.4.1, Gambar 4.5, Tabel 4.4 | [`prototipe-kg/ontology/tbox-v0.1.ttl`](../prototipe-kg/ontology/tbox-v0.1.ttl), [`docs/03-ontologi.md`](03-ontologi.md) |
| 5 | **Pemetaan STIX → RDF.** Relasi STIX menjadi *resource*; CVE STIX langsung memakai IRI SEPSES. | Subbab 4.4.2–4.4.3 | [`prototipe-kg/pipeline/build_kg.py`](../prototipe-kg/pipeline/build_kg.py) blok OpenCTI/STIX; [`docs/02-panduan-kode.md`](02-panduan-kode.md) Langkah 2 |
| 6 | ***Provenance* per laporan.** Satu graf bernama per laporan, karena waktu bukti melekat pada laporan. | Subbab 3.1.2, 3.5, 4.4.4 | `build_kg.py` bagian "Isi laporan: satu graf bernama per laporan"; [`data-checks/kuant01_opencti_prototype_findings.out.txt`](../data-checks/kuant01_opencti_prototype_findings.out.txt) bagian A–B |
| 7 | ***Exposure* aset dengan tiga nilai.** TRUE/FALSE/UNKNOWN beserta dasar pencocokannya. | Subbab 3.8, 4.6.1 | `build_kg.py` blok "exposure (diturunkan)"; [`queries/cq1-exposure-aset.rq`](../prototipe-kg/queries/cq1-exposure-aset.rq) |
| 8 | **Validasi.** SHACL memastikan syarat minimum agar CQ bisa dijawab. | Subbab 3.7, 4.4.1 | [`prototipe-kg/shapes/shapes-v0.1.ttl`](../prototipe-kg/shapes/shapes-v0.1.ttl), [`output/laporan-shacl-v0.1.txt`](../prototipe-kg/output/laporan-shacl-v0.1.txt) |
| 9 | **KG di triplestore.** Fuseki TDB2 lokal. | Subbab 4.2.3, Tabel 4.3 | [`prototipe-kg/fuseki/`](../prototipe-kg/fuseki/) |
| 10 | **Keabsahan waktu per t.** Kueri naif vs sah-waktu memberi jawaban berbeda. | Subbab 3.6, 4.6.2, 4.7.2 | [`queries/cq3-konteks-ancaman-naif.rq`](../prototipe-kg/queries/cq3-konteks-ancaman-naif.rq) vs [`cq3-konteks-ancaman-per-t.rq`](../prototipe-kg/queries/cq3-konteks-ancaman-per-t.rq); [`docs/04-kueri-cq.md`](04-kueri-cq.md) |
| 11 | **Relevansi per laporan.** Sektor dibaca dari laporan yang sama dengan CVE. | Subbab 4.5 (CQ4), Tabel 4.11 | [`queries/cq4-relevansi-sektor-negara.rq`](../prototipe-kg/queries/cq4-relevansi-sektor-negara.rq), [`data-checks/relevance_discrimination.out.txt`](../data-checks/relevance_discrimination.out.txt) |
| 12 | **Hasil dan iterasi.** CQ mana yang sudah terjawab, mana yang belum. | Subbab 4.9.2, Tabel 4.12 | [`prototipe-kg/hasil/hasil-cq-v0.1.md`](../prototipe-kg/hasil/hasil-cq-v0.1.md), [`prototipe-kg/README.md`](../prototipe-kg/README.md) bagian 2, visualisasi `hasil/visualisasi-abox-v0.1.html` |
| 13 | **Temuan yang muncul dari konstruksi**, lalu diukur pada seluruh korpus. | Subbab 4.9.1, Tabel 4.11 | [`data-checks/kuant01_*.out.txt`](../data-checks/kuant01_opencti_prototype_findings.out.txt), [`kuant02_*.out.txt`](../data-checks/kuant02_cve_layer_findings.out.txt) |

## B. Dari proposal ke kode

| Proposal | Isi | File |
|---|---|---|
| Subbab 3.1.2 | RDF *dataset* dan *named graph* | `prototipe-kg/pipeline/build_kg.py` (graf per laporan), `output/kg-sampel-v0.1.trig` |
| Subbab 3.6 | Tiga jenis waktu, definisi *admissibility* | `queries/cq3-konteks-ancaman-per-t.rq`, `cq5-status-bukti-per-t.rq` |
| Subbab 3.7 | SHACL | `shapes/shapes-v0.1.ttl`, `pipeline/validate_kg.py` |
| Subbab 3.8 | CPE, rentang versi, logika tiga nilai | `build_kg.py` fungsi `vtuple`, blok *exposure* |
| Subbab 4.2.2, Gambar 4.2, Tabel 4.2 | OpenCTI berbasis Docker, konektor | `infrastruktur/opencti/docker-compose.yml`, `.env.example`, `README.md` |
| Subbab 4.2.3, Tabel 4.3 | Kebutuhan perangkat (Python, rdflib, pyshacl, Fuseki) | `prototipe-kg/requirements.txt`, `prototipe-kg/fuseki/` |
| Subbab 4.3, Gambar 4.3 tahap 4–6, 8a | Rekayasa ontologi, pemetaan, penalaran, cek CQ | `prototipe-kg/` seluruhnya; `jalankan.sh` menjalankan urutannya |
| Subbab 4.4.1, Gambar 4.5, Tabel 4.4 | T-box dan *trace* istilah→CQ | `ontology/tbox-v0.1.ttl` (setiap istilah `ext:` mencatat CQ) |
| Subbab 4.4.2 | Perluasan pemetaan STIX | `build_kg.py` blok OpenCTI/STIX |
| Subbab 4.4.3 | *Entity linking* | `build_kg.py` blok penentuan IRI (CVE → IRI SEPSES; sektor/negara → IRI dari nama) |
| Subbab 4.4.4 | *Provenance* per laporan | `build_kg.py` (graf bernama + `g:report-metadata`), `queries/cq6-provenance.rq` |
| Subbab 4.5, Tabel 4.5 | CQ1–CQ8 dan CQ3b | `queries/cq*.rq` (CQ1–CQ7; CQ3b dan CQ8 belum) |
| Subbab 4.5.1, Gambar 4.6, Tabel 4.6 | Contoh terapan CVE-2025-8088 | `data-checks/cq_worked_example.out.txt`; `hasil/visualisasi-abox-v0.1.html` |
| Subbab 4.6.1 | *Exposure* aset | `build_kg.py` blok *exposure*; `data/aset-skenario.csv` |
| Subbab 4.6.2 | *Admissibility* per t | `queries/cq3-…-per-t.rq`, `cq4-…`, `cq5-…`, `cq7-…`; `pipeline/run_queries.py` (skenario t dan W) |
| Subbab 4.7.2 | Titik waktu t dan jendela W | `run_queries.py` variabel `SCENARIOS` |
| Subbab 4.9.1, Tabel 4.11 | Temuan pendahuluan dan implikasinya | `data-checks/*.out.txt` |
| Subbab 4.9.2, Tabel 4.12 | Prototipe KG v0.1 dan status CQ | `prototipe-kg/README.md`, `hasil/hasil-cq-v0.1.md` |
| Lampiran A (K3, K4, K14–K16) | Keputusan teknis | `prototipe-kg/README.md` bagian 4 (pilihan desain v0.1) |

## C. Dari skrip data ke angka di proposal

Semua skrip membaca data mentah secara *read-only* dengan
`python3 -I <skrip> <akar_proyek>`. Data mentah tidak ada di repositori; keluarannya
(`*.out.txt`) disertakan.

| Skrip | Angka yang dihasilkan | Dipakai di proposal |
|---|---|---|
| `threat_context_profile.py` | Konteks ancaman per CVE: aktor 77%, *malware* 94%, teknik 93%; 62 kelas sektor | Tabel 1.1, Tabel 4.11 |
| `kev_timing.py` | Laporan CTI umumnya terbit sesudah CVE masuk KEV | Subbab 1.1, Tabel 4.11 |
| `kev_label_windows.py`, `temporal_label_feasibility.py` | Label "masuk KEV sesudah t" hanya 0–8 positif | Tabel 4.11 (alasan tidak memprediksi eksploitasi) |
| `stale_context_profile.py` | 45,8% asosiasi bocor pada t = 30 Sep 2025; 51,4% usang pada t = 31 Des 2025 (W = 90) | Ringkasan, Tabel 1.1, Subbab 4.7.2 |
| `relevance_discrimination.py` | Relevansi sektor transitif 58,0% vs per laporan 39,2% (Government) | Tabel 4.11, CQ4 |
| `cq_instance_examples.py`, `cq_worked_example.py` | Instans konkret untuk setiap CQ; contoh CVE-2025-8088; lima nama Lazarus | Subbab 1.1, 4.4.3, 4.5.1, Gambar 4.6 |
| `kuant01_opencti_prototype_findings.py` | Waktu relasi = waktu impor; relasi multi-laporan; penerbit asli; varian nama; *indicator* untuk CQ3b | Tabel 4.11, Subbab 4.9.2, Lampiran A K3/K14/K15/K16 |
| `kuant02_cve_layer_findings.py` | Cakupan CVE 271/352; CVSS v4 saja 15,5%; `defaultStatus` *unknown* 75,4% | Tabel 1.1, Tabel 4.11 |

## D. Dari kode ke proposal

Setiap skrip di `prototipe-kg/pipeline/` mencantumkan subbab proposal yang diwujudkannya
pada *docstring* paling atas:

| File | Subbab proposal |
|---|---|
| `pipeline/extract_sample.py` | 4.3 (tahap 5: mulai dari sampel kecil), 4.9.2 |
| `pipeline/build_kg.py` | 4.4.1–4.4.4, 4.6.1 |
| `pipeline/validate_kg.py` | 3.7, 4.4.1 |
| `pipeline/run_queries.py` | 4.5, 4.6.2, 4.7.2, 4.9.2 |
| `pipeline/visualize.py` | 4.3 (tahap 5: visualisasi), 4.5.1 |
| `ontology/tbox-v0.1.ttl` | 4.4.1, Gambar 4.5, Tabel 4.4 |
| `shapes/shapes-v0.1.ttl` | 3.7, 4.4.1 |
| `queries/cq*.rq` | 4.5 (Tabel 4.5), 4.6.2 |
