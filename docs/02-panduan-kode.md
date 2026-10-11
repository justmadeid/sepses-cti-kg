# Panduan Kode Prototipe KG v0.1 (Langkah demi Langkah)

Dokumen ini menjelaskan setiap skrip di [`prototipe-kg/pipeline/`](../prototipe-kg/pipeline/)
secara berurutan, termasuk contoh data sebelum dan sesudah diproses. Nomor baris merujuk
ke versi v0.1 (11 Oktober 2026). Bila kode berubah, cari judul blok komentar
`# ---- <nama blok>` yang disebut di setiap bagian.

## 0. Konsep yang dipakai

| Istilah | Arti singkat | Contoh dari data |
|---|---|---|
| Objek STIX | Satu entitas CTI dalam JSON, punya `id` berbentuk `tipe--uuid` | `{"id": "intrusion-set--888b…", "type": "intrusion-set", "name": "Bitter"}` |
| Relasi STIX | Objek `relationship` yang menghubungkan dua objek | `source_ref` = Bitter, `relationship_type` = `targets`, `target_ref` = CVE-2025-8088 |
| Laporan STIX | Objek `report`; `object_refs` berisi daftar semua objek dan relasi yang dimuatnya | Laporan "Bitter (APT-Q-37) uses diverse means…", terbit 2025-10-23 |
| Triple RDF | Satu fakta: subjek – predikat – objek | `<…/RomCom> rdf:type cat:intrusion-set` |
| IRI | Nama unik global untuk sebuah *resource* | `http://w3id.org/sepses/resource/cve/CVE-2025-8088` |
| Prefiks | Singkatan IRI | `cat:` = `http://w3id.org/sepses/vocab/ref/attack#` |
| Graf bernama | Sekumpulan triple yang diberi nama (IRI); satu file TriG bisa memuat banyak graf | Graf `<…/report/8e069f1a…>` berisi isi laporan Bitter |
| T-box / A-box | T-box = skema (kelas, relasi); A-box = instans (data) | T-box: kelas `cat:intrusion-set`. A-box: RomCom adalah instansnya |

## Gambaran umum

[`jalankan.sh`](../prototipe-kg/jalankan.sh) menjalankan lima langkah berurutan:

| Langkah | Skrip | Apa yang dikerjakan | Butuh data mentah? |
|---|---|---|---|
| 1 | `extract_sample.py` | Mengambil 7 laporan dari ekspor OpenCTI, menyalin rekaman CVE dan KEV yang dibutuhkan | Ya |
| 2 | `build_kg.py` | Memetakan semuanya ke RDF dan menyimpan satu file TriG | Tidak |
| 3 | `validate_kg.py` | Memeriksa KG dengan SHACL | Tidak |
| 4 | `run_queries.py` | Menjalankan kueri CQ untuk beberapa waktu keputusan t | Tidak |
| 5 | `visualize.py` | Membuat visualisasi A-box interaktif | Tidak |

Dengan opsi `--fuseki`, sesudah langkah 5 file TriG juga dimuat ke Fuseki dan langkah 4
diulang terhadap Fuseki.

---

## Langkah 1 — `extract_sample.py`: mengambil sampel

**Tujuan.** Memilih sampel kecil yang tetap utuh: setiap laporan dibawa bersama semua
objek dan relasi yang dimuatnya. Proposal: Subbab 4.3 tahap 5 ("mulai dari sampel kecil").

| Baris | Isi | Penjelasan |
|---|---|---|
| 28–30 | `SAMPLE_CVES`, `KEEP_TYPES` | Tiga CVE contoh dan tipe objek yang dibawa. `indicator` dan *observable* sengaja tidak dibawa pada v0.1 (lihat keputusan K14). |
| 36–40 | memuat 8 file | Semua objek dari 8 file potongan dimasukkan ke kamus `objs` dengan kunci `id`. Objek yang muncul di beberapa file cukup disimpan sekali. |
| 42–45 | mencari laporan | `vuln_id` memetakan nama CVE ke `id` objek `vulnerability`. Laporan dipilih bila `object_refs`-nya memuat salah satu CVE contoh. Hasil: 7 laporan, diurutkan menurut tanggal terbit. |
| 47–52 | putaran 1: objek | Laporan dan semua objek non-relasi yang dirujuknya dimasukkan ke `keep`. |
| 54–58 | putaran 2: relasi | Relasi baru dibawa bila **kedua** ujungnya (`source_ref` dan `target_ref`) sudah ada di `keep`. Relasi `indicator indicates malware` tidak dibawa, karena `indicator` tidak ada di `keep`. Itulah alasan dua putaran. |
| 59–61 | pembuat laporan | Identitas pembuat (`created_by_ref`, yaitu AlienVault) ikut dibawa untuk *provenance*. |
| 63–66 | simpan sampel | Ditulis sebagai *bundle* STIX: `data/sampel-stix-v0.1.json`. |
| 68–84 | salin CVE dan KEV | Untuk setiap CVE di sampel, rekaman CVE List v5 disalin apa adanya ke `data/cve-records/`. Entri KEV yang relevan disalin ke `data/kev-sampel.json`, beserta versi katalog dan SHA-256 sumbernya. Sesudah ini langkah 2–5 tidak membutuhkan data mentah. |
| 86–95 | ringkasan | `data/sampel-stix-v0.1.txt` mencatat SHA-256 sampel, daftar laporan, dan jumlah objek per tipe. SHA-256 dipakai untuk memastikan sampel tidak berubah antar-*run*. |

**Hasil:** 7 laporan, 5 *intrusion set*, 15 *malware*, 50 teknik, 23 CVE, 10 sektor,
14 negara, 837 relasi. Rekaman CVE ditemukan untuk 14 dari 23 CVE; 9 CVE lama (sebelum 2025)
tidak ada di salinan CVE List v5 lokal.

**Coba sendiri.** Tambahkan `"CVE-2025-25256"` ke `SAMPLE_CVES`, jalankan langkah 1, lalu
lihat berapa laporan yang bertambah di `data/sampel-stix-v0.1.txt`.

---

## Langkah 2 — `build_kg.py`: pemetaan ke RDF

**Tujuan.** Mengubah sampel STIX, rekaman CVE, KEV, dan aset skenario menjadi satu KG
dengan graf bernama. Proposal: Subbab 4.4.1–4.4.4 dan 4.6.1.

### 2a. Namespace dan graf (baris 29–49)

Baris 31–37 mendefinisikan namespace. `CVE`, `CVSS`, dan `CAT` adalah kosakata SEPSES
yang dipakai ulang; `EXT` adalah perluasan penelitian ini; `RES` untuk IRI instans buatan
penelitian ini. Baris 39–40 menamai delapan graf:

| Graf | Isi | Diisi di blok |
|---|---|---|
| `g:tbox` | T-box dari `ontology/tbox-v0.1.ttl` | baris 48 |
| `g:opencti-entities` | Aktor, *malware*, teknik, CVE, sektor, negara: tipe dan nama | 2d |
| satu graf per laporan | Relasi STIX dan objek yang disebut laporan itu | 2e |
| `g:report-metadata` | Judul, tanggal terbit, pembuat, URL setiap laporan | 2e |
| `g:cve-sepses` | CVE, CWE, CVSS, produk terdampak | 2f |
| `g:kev` | Tanggal masuk KEV | 2g |
| `g:assets` | Organisasi dan aset skenario | 2h |
| `g:derived-exposure` | Hasil penilaian *exposure* | 2i |

Pemisahan ini membuat setiap fakta jelas asalnya. Kueri bisa memilih graf mana yang
dipakai, misalnya hanya graf laporan yang terbit sebelum t.

### 2b. Fungsi bantu (baris 52–57)

- `slug("United States of America")` → `united-states-of-america`. Dipakai untuk IRI dari
  nama (sektor, negara, aset).
- `cve_iri("CVE-2025-8088")` → `http://w3id.org/sepses/resource/cve/CVE-2025-8088`, yaitu
  **IRI yang sama dengan SEPSES**.

### 2c. Menentukan IRI setiap objek STIX (baris 63–78)

Inilah *entity linking* versi v0.1 (Subbab 4.4.3):

| Objek STIX | IRI | Alasan |
|---|---|---|
| `vulnerability` | IRI CVE SEPSES dari nama objek | Nama objek adalah ID CVE, sehingga tautan ke SEPSES cocok persis. KG ini bisa digabung dengan SEPSES tanpa tautan tambahan. |
| `identity` kelas (sektor) | `res:sector/<nama>` | Sektor organisasi skenario ("Government") otomatis menunjuk IRI yang sama. |
| `location` negara | `res:country/<nama>` | Sama seperti sektor. |
| `identity` lain (pembuat) | `res:agent/<nama>` | AlienVault menjadi `prov:Agent`. |
| `report` | `res:report/<uuid>` | IRI ini sekaligus menjadi **nama graf** laporan. |
| lainnya (aktor, *malware*, teknik, relasi) | `res:stix/<id STIX>` | Belum ditautkan ke IRI ATT&CK; ini tugas *entity linking* v0.2. |

### 2d. Entitas (baris 80–99)

Setiap aktor, *malware*, dan teknik mendapat `rdf:type` (misalnya `cat:intrusion-set`, pola
ICS-SEC), `rdfs:label` (nama), dan `ext:stixId` (ID asli, untuk menelusur balik ke
OpenCTI). Teknik juga mendapat ID ATT&CK (`dcterm:identifier`, misalnya `T1204`).

### 2e. Laporan dan graf bernama (baris 101–125)

Ini bagian inti *provenance* per laporan (Subbab 4.4.4).

1. **Metadata laporan** (baris 104–111) masuk `g:report-metadata`: judul, `ext:published`
   (tanggal terbit, satu-satunya waktu bukti yang dipakai), pembuat
   (`prov:wasAttributedTo`), dan semua URL (`ext:sourceUrl`).
2. **Isi laporan** (baris 113–125) masuk graf yang namanya IRI laporan. Untuk setiap isi
   `object_refs`:
   - bila relasi: relasi menjadi *resource* `cat:relationship` dengan `cat:hasSourceRef`,
     `cat:hasTargetRef`, dan `cat:relationshipType` (pola ICS-SEC);
   - bila objek lain: ditulis `laporan ext:mentions objek`.

**Contoh sebelum dan sesudah.** Relasi STIX dalam laporan Bitter:

```json
{
  "id": "relationship--f1051d4f-6c17-4835-91e8-4a158ef54116",
  "type": "relationship",
  "relationship_type": "targets",
  "source_ref": "intrusion-set--888b253e-4645-595a-a196-60a437370859",
  "target_ref": "vulnerability--e989673c-8484-5fa4-86c4-4246f623d809",
  "created": "2026-03-05T10:12:49.824Z"
}
```

menjadi RDF di dalam graf laporan Bitter (`output/kg-sampel-v0.1.trig`):

```turtle
<http://example.org/jejak-vp/resource/report/8e069f1a-0c06-53d0-9c35-8f4f69704494> {
    res:stix/relationship--f1051d4f-… a cat:relationship ;
        cat:hasSourceRef res:stix/intrusion-set--888b253e-… ;   # Bitter
        cat:hasTargetRef cveres:CVE-2025-8088 ;                   # IRI SEPSES
        cat:relationshipType "targets" .
}
```

dan metadata laporannya di `g:report-metadata`:

```turtle
res:report/8e069f1a-… a ext:Report ;
    dcterm:title "Bitter (APT-Q-37) uses diverse means to deliver new backdoor components" ;
    ext:published "2025-10-23T08:07:57.672000+00:00"^^xsd:dateTime ;
    prov:wasAttributedTo res:agent/alienvault ;
    ext:sourceUrl "https://otx.alienvault.com/pulse/68f9e25d…",
                  "https://ti.qianxin.com/blog/articles/bitter-uses-diverse-means-…" .
```

Perhatikan: `created` relasi (2026-03-05) **tidak dipetakan**, karena itu waktu impor.
Waktu bukti relasi ini adalah tanggal terbit laporan yang memuatnya (2025-10-23). Bila
relasi yang sama dimuat laporan lain, relasi itu juga ditulis di graf laporan tersebut,
sehingga kedua tanggal tetap terlacak.

### 2f. Lapisan CVE (baris 127–178)

Untuk setiap CVE yang rekamannya ada di `data/cve-records/`:

| Baris | Isi rekaman CVE List v5 | RDF |
|---|---|---|
| 138–141 | ID dan tanggal publikasi | `cve:CVE`, `dcterm:identifier`, `dcterm:issued` |
| 142–145 | `problemTypes` (CWE) | `cve:hasCWE` → IRI CWE SEPSES |
| 146–155 | metrik `cvssV3_x` (CNA atau ADP) | simpul `cvss:CVSS3BaseMetric` dengan `cvss:baseScore`, `baseSeverity`, `vectorString` |
| 156–157 | metrik `cvssV4_0` | `ext:cvssV4BaseScore` (literal sementara, karena SEPSES belum punya kelas CVSS v4) |
| 158–178 | `affected` | satu `ext:AffectedProduct` per entri (vendor, produk, `defaultStatus`, CPE bila ada) dan satu simpul per entri versi: rentang (`versionStart` + `versionEndIncluding`/`versionEndExcluding`) atau versi tunggal (`versionExact`) |

Contoh: CVE-2025-8088 punya satu produk terdampak `win.rar GmbH / WinRAR` dengan rentang
`0 .. <= 7.12 (affected)` dan `defaultStatus = unknown`.

### 2g. KEV (baris 180–187)

Untuk CVE yang ada di KEV: `ext:kevDateAdded` (tanggal masuk KEV) dan
`ext:kevRansomwareUse`. Status KEV per t dihitung saat kueri (`kevDateAdded <= t`), bukan
disimpan, karena t berbeda-beda.

### 2h. Aset skenario (baris 189–205)

Organisasi "Pemerintah Daerah X" mendapat `ext:inSector` dan `ext:inCountry` yang menunjuk
IRI sektor/negara yang **sama** dengan IRI dari OpenCTI (lewat `slug`). Inilah yang membuat
CQ4 bisa mencocokkan sektor organisasi dengan sektor di laporan. Lima aset dari
`data/aset-skenario.csv` mendapat vendor, produk, dan versi terpasang.

### 2i. Penilaian *exposure* (baris 208–261)

Proposal: Subbab 3.8 dan 4.6.1. Untuk setiap pasangan CVE × aset:

```text
1. Cocokkan nama produk (dinormalisasi: huruf kecil, tanpa spasi/tanda baca).
   Vendor sengaja tidak dipakai: CVE-2025-8088 mencatat "win.rar GmbH", sedangkan
   CVE-2025-6218 dan KEV mencatat "RARLAB".
2. Ubah versi menjadi tuple angka: "7.11 (64-bit)" -> (7, 11)          [vtuple, baris 209]
3. Periksa setiap entri versi pada rekaman CVE:
   - rentang: apakah versi aset ada di [start, end] (<=) atau [start, end) (<)?
   - versi tunggal: apakah sama persis?
   Bila cocok: status entri "affected" -> TRUE, "unaffected" -> FALSE, lainnya -> UNKNOWN.
4. Bila tidak ada entri yang cocok: pakai defaultStatus.
   affected -> TRUE, unaffected -> FALSE, unknown atau tidak diisi -> UNKNOWN.
   (Skema CVE 5: defaultStatus yang tidak diisi berarti "unknown".)
5. Simpan sebagai ext:ExposureAssessment beserta ext:matchBasis (kalimat alasan)
   dan prov:wasGeneratedBy (aktivitas pencocokan).
```

Hasil pada lima aset skenario:

| Aset | Versi | CVE | Status | Aturan yang berlaku |
|---|---|---|---|---|
| WS-PEMDA-01 | WinRAR 7.10 | CVE-2025-8088 | TRUE | di dalam rentang `0 .. <= 7.12` |
| WS-PEMDA-01 | WinRAR 7.10 | CVE-2025-6218 | UNKNOWN | hanya versi 7.11 tercatat; `defaultStatus = unknown` |
| WS-PEMDA-02 | WinRAR 7.11 | CVE-2025-6218 | TRUE | sama dengan versi tercatat `7.11 (64-bit)` |
| WS-PEMDA-03 | WinRAR 7.13 | CVE-2025-8088 | UNKNOWN | di luar rentang, tetapi `defaultStatus = unknown` (tidak dinyatakan aman) |
| WAF-PEMDA-01 | FortiWeb 7.4.5 | CVE-2025-64446 | TRUE | di dalam rentang `7.4.0 .. <= 7.4.9` |
| WAF-PEMDA-02 | FortiWeb 7.4.10 | CVE-2025-64446 | FALSE | tidak tercantum; `defaultStatus = unaffected` |

Kenapa dihitung di Python, bukan SPARQL? Perbandingan versi (7.10 < 7.12) sulit dan rawan
salah bila dikerjakan dengan string di SPARQL. Hasilnya tetap disimpan di KG beserta
alasan dan *provenance*-nya, sehingga CQ1 cukup membaca graf `g:derived-exposure`.

**Keterbatasan v0.1.** Bila satu CVE punya lebih dari satu entri `affected` untuk produk
yang sama, penilaian untuk pasangan aset–CVE itu ditulis lebih dari sekali ke IRI yang
sama. Kasus ini tidak terjadi pada sampel; aturan penggabungannya (TRUE > UNKNOWN > FALSE)
dikerjakan pada v0.2.

### 2j. Menyimpan secara deterministik (baris 264–291)

`write_trig_sorted` menulis graf berurutan menurut IRI. Tanpa ini, rdflib menulis graf
dalam urutan acak setiap *run*, dan Git akan menunjukkan perubahan palsu. Sesudahnya,
`output/statistik-kg-v0.1.txt` mencatat jumlah triple per graf (total 4.739).

---

## Langkah 3 — `validate_kg.py`: validasi SHACL

**Tujuan.** Memastikan data memenuhi syarat minimum agar CQ bisa dijawab. Proposal:
Subbab 3.7 dan 4.4.1.

| Baris | Isi |
|---|---|
| 23–28 | Memuat TriG, lalu menggabungkan semua graf **kecuali T-box** menjadi satu graf data. SHACL memeriksa data (A-box), bukan skema. |
| 29 | Memuat [`shapes/shapes-v0.1.ttl`](../prototipe-kg/shapes/shapes-v0.1.ttl). |
| 31 | `pyshacl.validate(...)`. `allow_warnings=True`: *warning* tidak membuat hasil gagal. |
| 33–50 | Mengelompokkan hasil per tingkat (*Violation*/*Warning*) dan pesan, lalu menulis `output/laporan-shacl-v0.1.txt`. |

Isi *shapes*:

| *Shape* | Syarat | Tingkat | Kenapa |
|---|---|---|---|
| `ReportShape` | tepat satu `ext:published` bertipe `xsd:dateTime`; ada pembuat dan judul | Violation | Tanpa tanggal terbit, CQ5 tidak bisa dijawab |
| | ada `ext:sourceUrl` | Warning | Laporan tanpa URL sulit diverifikasi |
| `RelationshipShape` | tepat satu sumber, target, dan tipe relasi yang dikenal | Violation | Relasi tidak lengkap tidak bisa dikueri |
| `CVEShape` | punya `dcterm:identifier` berpola `CVE-YYYY-NNNN` | Warning | Muncul untuk 9 CVE yang tidak punya rekaman CVE; CQ1–CQ2 untuk CVE itu tidak lengkap |
| `ExposureShape` | status ∈ {TRUE, FALSE, UNKNOWN}; ada aset, CVE, alasan, dan *provenance* | Violation | CQ1 wajib disertai dasar pencocokan |
| `KEVShape` | `ext:kevDateAdded` bertipe `xsd:date` | Violation | Perbandingan dengan t butuh tipe tanggal |

**Hasil:** lolos (0 *violation*), 9 *warning*.

**Coba sendiri.** Di `build_kg.py`, beri komentar pada baris yang menambahkan
`ext:published` (baris 106), jalankan langkah 2 dan 3, lalu lihat 7 *violation* muncul.
Kembalikan sesudahnya.

---

## Langkah 4 — `run_queries.py`: menjalankan CQ

**Tujuan.** Menjalankan setiap file `queries/*.rq` dan menyimpan hasilnya sebagai tabel.
Proposal: Subbab 4.5, 4.6.2, 4.7.2, dan Tabel 4.12.

| Baris | Isi | Penjelasan |
|---|---|---|
| 21 | nilai bawaan t | Setiap kueri bergantung waktu ditulis dengan t = 30 Sep 2025 dan tMulai = t − 180 hari = 3 Apr 2025, sehingga bisa langsung dijalankan di UI Fuseki. |
| 24–26 | `SCENARIOS` | Tiga skenario: (30 Sep 2025, W = 180), (31 Des 2025, W = 180), (31 Des 2025, W = 90). Sesuai Subbab 4.7.2. |
| 27 | `TIME_FREE` | Kueri yang tidak bergantung waktu hanya dijalankan sekali. |
| 30–34 | `with_scenario` | Mengganti tanggal bawaan di teks kueri dengan t dan tMulai skenario. |
| 37–40 | `run_local` | Menjalankan kueri dengan rdflib terhadap file TriG. |
| 43–48 | `run_endpoint` | Menjalankan kueri lewat HTTP ke Fuseki (protokol SPARQL, hasil JSON). |
| 60–87 | `main` | Untuk setiap file `.rq`: ambil baris komentar `#` sebagai deskripsi, jalankan per skenario, tulis ke `hasil/hasil-cq-v0.1.md`. |

Hasil rdflib dan Fuseki sudah diperiksa sama persis. Itu bukti bahwa kueri tidak
bergantung pada satu mesin. Penjelasan isi setiap kueri ada di
[`04-kueri-cq.md`](04-kueri-cq.md).

---

## Langkah 5 — `visualize.py`: visualisasi A-box

**Tujuan.** Menggambar A-box agar relasi bisa diperiksa secara visual. Proposal:
Subbab 4.3 tahap 5 dan Gambar 4.6.

| Baris | Isi |
|---|---|
| 46–61 | Kueri aset → organisasi → sektor dan aset → CVE (status *exposure*) |
| 63–85 | Untuk CVE yang terkait aset: CWE, skor CVSS, tanggal KEV |
| 87–111 | Laporan yang menyebut CVE, aktor/*malware* yang menargetkan CVE menurut laporan itu, dan sektor yang disebut laporan. Setiap sisi yang berasal dari laporan diberi tanggal terbit laporan. |
| 113–118 | Menghapus sisi ganda |
| 119–121 | Menyisipkan data ke `pipeline/visualisasi-template.html` |

Di halaman HTML, pilihan **Waktu keputusan** menyembunyikan sisi dengan tanggal di luar
jendela [t − W, t], dan sisi KEV dengan tanggal sesudah t. Logika ini sama dengan kueri
sah-waktu di langkah 4.

---

## `jalankan.sh`

```text
ROOT = $JEJAK_DATA_ROOT atau dua folder di atas
bila ada data mentah  -> langkah 1, selain itu dilewati
langkah 2, 3, 4, 5
--fuseki: docker compose up (fuseki/), tunggu /$/ping, PUT TriG ke /jejak/data,
          lalu langkah 4 terhadap endpoint
```

Fuseki dibangun dari rilis resmi Apache 5.6.0 dengan pemeriksaan SHA-512
([`fuseki/Dockerfile`](../prototipe-kg/fuseki/Dockerfile)), dataset TDB2 bernama `jejak`
([`fuseki/config.ttl`](../prototipe-kg/fuseki/config.ttl)), dan hanya terbuka di
`127.0.0.1`.

## Latihan untuk memahami kode

1. **Aset baru.** Tambahkan baris `WS-PEMDA-04,Workstation lab,RARLAB,WinRAR,6.24,uji` ke
   `data/aset-skenario.csv`, jalankan `./jalankan.sh`. Tebak dulu status CVE-2025-8088
   dan CVE-2025-6218 untuk aset itu, lalu cocokkan dengan `hasil/hasil-cq-v0.1.md`
   (jawaban: TRUE dan UNKNOWN).
2. **Waktu keputusan lain.** Tambahkan skenario `("t = 31 Okt 2025, W = 180", "2025-10-31", 180)`
   ke `SCENARIOS`. Apakah Bitter muncul di CQ3? (Ya, laporannya terbit 23 Oktober.)
3. **Telusuri satu fakta.** Di UI Fuseki, cari semua graf yang memuat relasi
   "RomCom targets CVE-2025-8088". Berapa laporan, dan kapan masing-masing terbit?
