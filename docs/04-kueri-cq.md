# Kueri SPARQL per CQ

Folder: [`prototipe-kg/queries/`](../prototipe-kg/queries/). Proposal: Subbab 4.5 (Tabel 4.5),
Subbab 4.6.2 (*admissibility*), Subbab 4.7.2 (t dan W). Hasil lengkap:
[`prototipe-kg/hasil/hasil-cq-v0.1.md`](../prototipe-kg/hasil/hasil-cq-v0.1.md).

## Cara membaca kueri

Setiap kueri menyebut graf secara eksplisit dengan `GRAPH`. Contohnya
`GRAPH g:cve-sepses { … }` berarti "cari di lapisan CVE". `GRAPH ?lap { … }` berarti
"cari di graf laporan mana pun", dan `?lap` sekaligus menjadi IRI laporannya, sehingga
tanggal terbitnya bisa dicari di `g:report-metadata`.

Kueri yang bergantung waktu memuat baris `VALUES` dengan t = 30 September 2025 dan
tMulai = t − 180 hari. Untuk skenario lain, ganti dua tanggal itu (di UI Fuseki), atau
biarkan `run_queries.py` menggantinya otomatis.

## Ringkasan

| File | CQ | Graf yang dipakai | Bergantung t? | Hasil (t = 30 Sep 2025, W = 180) |
|---|---|---|---|---|
| `cq1-exposure-aset.rq` | CQ1 | assets, derived-exposure, cve-sepses | tidak | 8 pasangan: 4 TRUE, 1 FALSE, 3 UNKNOWN |
| `cq2-keparahan.rq` | CQ2 | derived-exposure, cve-sepses | tidak | CVSS dan CWE untuk 3 CVE |
| `cq3-konteks-ancaman-naif.rq` | CQ3 (pembanding B1) | semua graf laporan, opencti-entities | tidak | 13 aktor/*malware* |
| `cq3-konteks-ancaman-per-t.rq` | CQ3 + CQ5 | graf laporan, report-metadata, opencti-entities | ya | 7 aktor/*malware* |
| `cq4-relevansi-sektor-negara.rq` | CQ4 | assets, derived-exposure, graf laporan, report-metadata | ya | Government: CVE-2025-6218 sah, CVE-2025-8088 belum sah |
| `cq5-status-bukti-per-t.rq` | CQ5 | derived-exposure, graf laporan, report-metadata | ya | Label BERLAKU / BELUM TERBIT / USANG per laporan |
| `cq6-provenance.rq` | CQ6 | graf laporan, opencti-entities, report-metadata | tidak | 5 pernyataan aktor→CVE dengan laporan, tanggal, pembuat, pulse OTX, penerbit asli |
| `cq7-status-kev-per-t.rq` | CQ7 | derived-exposure, kev | ya | Hanya CVE-2025-8088 berstatus KEV pada t |

## Penjelasan per kueri

### CQ1 — `cq1-exposure-aset.rq`

Membaca aset (`g:assets`), lalu penilaian *exposure*-nya (`g:derived-exposure`), lalu ID
CVE-nya (`g:cve-sepses`). Status dan alasan sudah dihitung `build_kg.py`, jadi kueri ini
hanya menggabungkan. Lihat [`02-panduan-kode.md`](02-panduan-kode.md) bagian 2i.

### CQ2 — `cq2-keparahan.rq`

Hanya CVE yang status *exposure*-nya bukan FALSE. `OPTIONAL` dipakai untuk CVSS v3, CVSS v4,
dan CWE karena tidak semua CVE punya ketiganya (CVE-2025-8088 hanya punya CVSS v4).
`GROUP_CONCAT` menggabungkan beberapa CWE menjadi satu kolom.

### CQ3 naif vs CQ3 per t

Bagian intinya sama:

```sparql
GRAPH ?lap { ?r cat:hasTargetRef ?c ; cat:relationshipType "targets" ; cat:hasSourceRef ?x . }
GRAPH g:opencti-entities { ?x a ?kelas ; rdfs:label ?nama . }
FILTER(?kelas IN (cat:intrusion-set, cat:malware))
```

Versi per t menambahkan dua baris:

```sparql
GRAPH g:report-metadata { ?lap ext:published ?terbit . }
FILTER(?terbit <= ?t && ?terbit >= ?tMulai)
```

Artinya: relasi hanya dipakai bila laporan yang memuatnya sudah terbit pada t dan belum
lebih tua dari W hari. Perbedaan hasil kedua kueri adalah inti masalah penelitian:

| Skenario | Naif | Per t | Yang hilang |
|---|---|---|---|
| t = 30 Sep 2025, W = 180 | 13 | 7 | Bitter, Earth Estries, dan *malware*-nya (laporan terbit Oktober = **belum terbit**) |
| t = 31 Des 2025, W = 180 | 13 | 13 | — |
| t = 31 Des 2025, W = 90 | 13 | 6 | RomCom dan *malware*-nya (laporan Agustus–September = **usang**) |

### CQ4 — `cq4-relevansi-sektor-negara.rq`

Kuncinya baris ini:

```sparql
GRAPH ?lap { ?lap ext:mentions ?c , ?konteks . }
```

CVE dan sektor/negara organisasi harus disebut **di graf laporan yang sama**. Relevansi
tidak diturunkan lewat rantai "CVE ← aktor → sektor" yang bisa berasal dari laporan
berbeda (definisi transitif terlalu luas: Government 58,0% dari CVE, sedangkan per laporan
39,2%). Kolom `sah_pada_t` menunjukkan apakah laporan pendukungnya sah pada t.

### CQ5 — `cq5-status-bukti-per-t.rq`

Memberi label setiap laporan pendukung:

```sparql
BIND(IF(?terbitWaktu > ?t, "BELUM TERBIT", IF(?terbitWaktu < ?tMulai, "USANG", "BERLAKU")) AS ?status_bukti)
```

"BELUM TERBIT" adalah bukti yang bocor dari masa depan bila dipakai pada t.

### CQ6 — `cq6-provenance.rq`

Untuk setiap pernyataan "aktor targets CVE": laporan, tanggal terbit, pembuat, dan URL.
URL dipisah menjadi dua kolom: `pulse_otx` (agregator) dan `sumber_asli` (penerbit asli,
misalnya welivesecurity.com atau ti.qianxin.com). Pemisahan ini menyiapkan *provenance*
dua tingkat (K15).

### CQ7 — `cq7-status-kev-per-t.rq`

```sparql
BIND(IF(BOUND(?kev_sejak) && ?kev_sejak <= ?t, "KEV", "belum KEV") AS ?status_kev_pada_t)
```

Pada t = 30 September 2025 hanya CVE-2025-8088 yang berstatus KEV (sejak 12 Agustus).
CVE-2025-64446 masuk 14 November dan CVE-2025-6218 masuk 9 Desember, sehingga pada
t = 31 Desember ketiganya berstatus KEV.

## Belum ada kuerinya

- **CQ3b** (*indicator* yang berlaku pada t): menunggu pemetaan *indicator* di v0.2.
- **CQ8** (tier prioritas): menunggu CQ1–CQ7 stabil.
