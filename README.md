# SEPSES-CTI KG — Integrasi CTI OpenCTI ke SEPSES Knowledge Graph

Repositori teknis tesis S2 Ilmu Komputer (Kecerdasan Artifisial), Universitas Gadjah Mada.

- **Mahasiswa:** Made Agastya
- **Pembimbing:** Kabul Kurniawan, Ph.D.
- **Status:** tahap proposal. Prototipe KG v0.1 pada sampel kecil sudah berjalan.

Repositori ini berisi kode, ontologi, kueri, dan hasil konstruksi *knowledge graph*,
sehingga perkembangannya bisa dipantau. Naskah proposal lengkap ada di
[`proposal/`](proposal/) (PDF). Peta hubungan proposal dan kode ada di
[`docs/00-peta-proposal-kode.md`](docs/00-peta-proposal-kode.md).

## Masalah yang diteliti (ringkas)

SEPSES KG dapat menemukan CVE yang memengaruhi aset organisasi, tetapi tidak tahu siapa
yang memakai CVE itu, terhadap sektor apa, dan kapan. OpenCTI (STIX 2.1) punya konteks
ancaman tersebut, tetapi tidak menalar produk dan versi aset. Bila keduanya digabung tanpa
memperhatikan waktu dan sumber, sebagian konteks ancaman menjadi keliru pada waktu
keputusan. Contohnya, pada t = 30 September 2025, 45,8% asosiasi CVE–ancaman berasal dari
laporan yang baru terbit sesudah tanggal itu.

Pertanyaan penelitian: bagaimana CTI STIX 2.1 dari OpenCTI dapat diintegrasikan ke SEPSES
KG sehingga pertanyaan penilaian kerentanan berbasis konteks ancaman dapat dijawab secara
benar, dapat ditelusuri sumbernya, dan sesuai waktu keputusan?

## Alur kerja yang diikuti

Sesuai arahan bimbingan pertemuan 1:

```text
use case dan CQ → taksonomi → kelas dan relasi (T-box) → pemetaan → KG (A-box) di triplestore
→ kueri SPARQL → CQ terjawab? → bila belum: perbaiki ontologi/pemetaan (v0.x) dan ulangi
```

Putaran pertama (v0.1) sudah dijalankan pada 7 laporan OpenCTI. Hasilnya ada di
[`prototipe-kg/README.md`](prototipe-kg/README.md) dan [`PROGRES.md`](PROGRES.md).

## Isi repositori

| Folder | Isi | Dokumentasi |
|---|---|---|
| [`prototipe-kg/`](prototipe-kg/) | Prototipe KG v0.1: T-box, SHACL, *pipeline* Python (5 langkah), kueri SPARQL CQ1–CQ7, Fuseki (Docker), hasil, visualisasi | [`docs/02-panduan-kode.md`](docs/02-panduan-kode.md), [`docs/03-ontologi.md`](docs/03-ontologi.md), [`docs/04-kueri-cq.md`](docs/04-kueri-cq.md) |
| [`data-checks/`](data-checks/) | Skrip *read-only* untuk mengukur realitas data OpenCTI, CVE, dan KEV (sumber angka di proposal), beserta keluarannya (`*.out.txt`) | [`docs/00-peta-proposal-kode.md`](docs/00-peta-proposal-kode.md) bagian C |
| [`infrastruktur/opencti/`](infrastruktur/opencti/) | Konfigurasi Docker OpenCTI + konektor AlienVault yang dipakai mengumpulkan data, dan skrip pemecah *bundle* STIX | [`docs/01-alur-data.md`](docs/01-alur-data.md) |
| [`proposal/`](proposal/) | Draft proposal terbaru (PDF) | — |
| [`progres/`](progres/) | `tracker.csv` (daftar tugas) dan `progress.py` (ringkasan progres) | `python3 progres/progress.py` |
| [`docs/`](docs/) | Dokumentasi: peta proposal↔kode, alur data, panduan kode, ontologi, kueri | — |

## Menjalankan prototipe

Prasyarat: Python 3.12. Docker hanya dibutuhkan untuk Fuseki.

```bash
cd prototipe-kg
./jalankan.sh            # langkah 2–5 dengan rdflib (tanpa Docker)
./jalankan.sh --fuseki   # juga memuat KG ke Fuseki lokal: http://localhost:3030 (dataset /jejak)
```

Langkah 1 (mengambil sampel dari ekspor OpenCTI penuh) hanya berjalan bila data mentah
tersedia. Data mentah tidak ada di repositori; hasil langkah 1 (`prototipe-kg/data/`)
sudah disertakan, sehingga langkah 2–5 bisa langsung dijalankan.

## Yang tidak disertakan

| Tidak disertakan | Alasan |
|---|---|
| Ekspor OpenCTI penuh (±560 MB), CVE List v5 (90.255 rekaman), *dump* SEPSES (±1 GB) | Ukuran. Sampel dan rekaman CVE/KEV yang dibutuhkan prototipe sudah disertakan di `prototipe-kg/data/` |
| `.env` OpenCTI | Berisi kredensial. Yang disertakan hanya `.env.example` dengan nilai `ChangeMe` |
| Sumber LaTeX proposal, catatan bimbingan, dan SLR | Bukan bagian teknis; disimpan di repositori penelitian lokal |

## Sumber data dan lisensi

- **OpenCTI / AlienVault OTX** (STIX 2.1, TLP:WHITE): sampel 7 laporan untuk keperluan riset.
- **CVE List v5**: rekaman CVE dari CVE Program (cve.org), sesuai *terms of use* CVE.
- **CISA KEV**: katalog publik pemerintah AS.
- **SEPSES / ICS-SEC KG**: kosakata dipakai ulang dengan merujuk namespace aslinya
  (`http://w3id.org/sepses/...`).

Catatan nama: identitas lama "JEJAK-VP" (nama kerangka v1) masih muncul pada namespace sementara
`http://example.org/jejak-vp/` dan nama dataset Fuseki `/jejak`; keduanya diganti pada prototipe v0.2.

Repositori ini disinkronkan dari folder penelitian lokal dengan
`research-v3/sinkron-ke-repo.sh`; ubahan kode dibuat di sana lalu disalin ke sini.
