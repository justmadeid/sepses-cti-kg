# SEPSES-CTI KG Integrasi CTI OpenCTI ke SEPSES Knowledge Graph

Repositori teknis tesis S2 Ilmu Komputer (Kecerdasan Artifisial), Universitas Gadjah Mada.

Repositori ini berisi kode, ontologi, kueri, dan hasil konstruksi *knowledge graph*,
sehingga perkembangannya bisa dipantau.

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

## Menjalankan prototipe

Prasyarat: Python 3.12. Docker hanya dibutuhkan untuk Fuseki.

```bash
cd sepses-cti-kg
./run.sh            # langkah 2–5 dengan rdflib (tanpa Docker)
./run.sh --fuseki   # juga memuat KG ke Fuseki lokal: http://localhost:3030 
```

Langkah 1 (mengambil sampel dari ekspor OpenCTI penuh) hanya berjalan bila data mentah
tersedia. Data mentah tidak ada di repositori; hasil langkah 1 (`prototipe-kg/data/`)
sudah disertakan, sehingga langkah 2–5 bisa langsung dijalankan.

## Yang tidak disertakan

| Tidak disertakan | Alasan |
|---|---|
| Ekspor OpenCTI penuh (±560 MB), CVE List v5 (90.255 rekaman), *dump* SEPSES (±1 GB) | Ukuran. Sampel dan rekaman CVE/KEV yang dibutuhkan prototipe sudah disertakan di `prototipe-kg/data/` |
| `.env` OpenCTI | Berisi kredensial. Yang disertakan hanya `.env.example` dengan nilai `ChangeMe` |
