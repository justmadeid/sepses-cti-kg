# Log Progres

Catatan perkembangan konstruksi KG dan bahan proposal, terbaru di atas. Daftar tugas
lengkap: [`progres/tracker.csv`](progres/tracker.csv) (`python3 progres/progress.py`).

## 2026-10-11 — Prototipe KG v0.1 dan konsolidasi

**Dikerjakan**
- Prototipe KG v0.1 pada 7 laporan OpenCTI (CVE-2025-8088 dan CVE-2025-6218 untuk WinRAR,
  CVE-2025-64446 untuk FortiWeb) dan 5 aset skenario: 4.739 *triple*, 14 graf bernama
  (satu per laporan). Disimpan di Apache Jena Fuseki 5.6.0 (TDB2, Docker).
- Kueri SPARQL CQ1–CQ7. Hasil: 5 CQ terjawab, CQ2 dan CQ6 sebagian, CQ8 belum dicoba.
- Validasi SHACL: 0 *violation*, 9 *warning* (CVE tanpa rekaman CVE).
- Visualisasi A-box interaktif dengan pilihan waktu keputusan t.
- Temuan prototipe diukur pada seluruh korpus (`data-checks/kuant01_*`, `kuant02_*`):
  - 100% dari 456.585 relasi STIX bertanggal impor (Maret 2026), sehingga waktu bukti
    diambil dari tanggal terbit laporan;
  - 11,5% relasi "X targets CVE" dimuat lebih dari satu laporan;
  - 98,4% laporan memuat URL penerbit asli (192 domain), padahal pembuatnya selalu
    konektor AlienVault;
  - 75,4% entri produk terdampak pada rekaman CVE berstatus bawaan *unknown*;
  - 15,5% CVE 2025 yang disebut CTI hanya punya CVSS v4.0 (belum ada di kosakata SEPSES).
- Keputusan lingkup *indicator* yang diusulkan (opsi B): dimodelkan tanpa *observable*,
  dipakai pada CQ3b. Menunggu konfirmasi pembimbing.
- Draft proposal v3-draft-13: penyelarasan gambar T-box dengan file ontologi, CQ3b,
  keputusan K14–K16.

**Menunggu bimbingan 2 (16 Oktober 2026)**
- K3: *provenance* RDF-star atau *named graph*; triplestore lab.
- K4: pemetaan Python atau RML/Java.
- K14: lingkup *indicator*. K15: *provenance* dua tingkat. K16: syarat `revoked` per t.

**Berikutnya (sesudah bimbingan)**
- Iterasi v0.2: pemetaan *indicator* dan CQ3b, *entity linking* varian nama aktor,
  *provenance* dua tingkat, CVSS v4, tautan SEPSES untuk CVE lama, CQ8.

## 2026-10-10 — Draft proposal dan analisis bimbingan 1

- Draft proposal v3 (Bab I–IV) dengan alur yang mengikuti arahan pertemuan 1.
- Gambar T-box, contoh A-box CVE-2025-8088, dan tabel jalur relasi per CQ.

## 2026-10-09 — Pemetaan masalah dan cek realitas data

- Skrip `data-checks/` untuk profil konteks ancaman, keterlambatan KEV, bukti bocor dan
  usang per t, serta relevansi sektor per laporan.
- Arsip konfigurasi OpenCTI (`infrastruktur/opencti/`).
