# Prototipe KG v0.1

Percobaan konstruksi *knowledge graph* pada **sampel kecil**, mengikuti alur kerja yang
diarahkan pembimbing pada pertemuan 1 (18 Juni 2026):

> *use case*/CQ → taksonomi → kelas dan relasi (T-box) → pemetaan → KG (A-box) di
> database → kueri SPARQL → CQ terjawab? → iterasi.

Tujuannya membuktikan bahwa rancangan di proposal dapat dijalankan. Prototipe ini bukan
hasil akhir tesis. Data lama di luar `research-v3/` tidak diubah; data mentah hanya dibaca.

Tanggal: 11 Oktober 2026.

## 1. Ringkasan hasil

| Ukuran | Nilai |
|---|---|
| Laporan OpenCTI dalam sampel | 7 (11 Agu – 25 Nov 2025), semuanya dari konektor AlienVault |
| CVE contoh | CVE-2025-8088 dan CVE-2025-6218 (WinRAR), CVE-2025-64446 (FortiWeb) |
| Objek STIX yang dipetakan | 7 laporan, 5 *intrusion set*, 15 malware, 50 teknik, 23 CVE, 10 sektor, 14 negara, 837 relasi |
| Aset skenario | 5 aset milik "Pemerintah Daerah X" (sektor Government, Indonesia) |
| Ukuran KG | **4.739 triple** dalam 14 graf bernama (1 graf per laporan) |
| Triplestore | Apache Jena Fuseki 5.6.0 (TDB2) di Docker, `http://localhost:3030`, dataset `/jejak` |
| Validasi SHACL | Lolos (0 *violation*); 9 *warning* untuk CVE tanpa rekaman CVE |
| CQ yang dicoba | CQ1–CQ7: **5 terjawab penuh, 2 terjawab sebagian**; CQ8 belum dicoba |
| Konsistensi | Hasil kueri di Fuseki sama dengan hasil rdflib in-memory |

## 2. Status setiap CQ

| CQ | Status | Hasil pada sampel | Catatan untuk iterasi v0.2 |
|---|---|---|---|
| CQ1 *exposure* aset | Terjawab | 8 pasangan aset–CVE: 4 TRUE, 1 FALSE, 3 UNKNOWN, masing-masing dengan dasar pencocokan | Pencocokan versi dihitung di skrip Python, lalu hasilnya disimpan sebagai graf turunan dengan PROV-O. Belum memakai CPE. |
| CQ2 keparahan | Sebagian | CVSS dan CWE tersedia untuk 3 CVE contoh | (a) SEPSES belum punya kelas CVSS v4.0, padahal CVE-2025-8088 hanya punya CVSS v4.0. (b) 9 dari 23 CVE di sampel (terbit sebelum 2025) tidak ada di salinan CVE List v5 lokal; sumber ini perlu diganti dengan tautan ke SEPSES. (c) CAPEC belum dimasukkan. |
| CQ3 konteks ancaman | Terjawab | Tanpa waktu: 13 aktor/malware. Pada t = 30 Sep 2025 (W = 180): hanya 7. **6 dari 13 (46%) berasal dari laporan yang terbit sesudah t.** | Varian nama belum disatukan ("RomCom" vs "RomCom, Paper Werewolf"; "Mythic" vs "Mythic C2 agent"). Ini tugas *entity linking*. |
| CQ4 relevansi sektor/negara | Terjawab | Sektor Government: CVE-2025-6218 (laporan 20 Agu, sah pada t = 30 Sep) dan CVE-2025-8088 (laporan Bitter 23 Okt, **belum sah** pada t = 30 Sep). Negara Indonesia: tidak ada laporan. | Jawaban kosong belum membedakan "tidak ada bukti" dari "sumber tidak meliput". |
| CQ5 status bukti per t | Terjawab | Setiap laporan diberi label BERLAKU / BELUM TERBIT / USANG per skenario t dan W | — |
| CQ6 *provenance* | Sebagian | Setiap pernyataan "aktor menargetkan CVE" dapat ditelusuri ke laporan, tanggal, pembuat, dan URL | Pembuat selalu "AlienVault" (konektor agregator). Penerbit asli (ESET, QiAnXin, Recorded Future) hanya tersimpan di URL, sehingga *provenance* perlu dua tingkat: agregator dan sumber asli. |
| CQ7 status KEV per t | Terjawab | Pada t = 30 Sep 2025 hanya CVE-2025-8088 yang berstatus KEV. Pada t = 31 Des 2025 ketiganya sudah KEV (CVE-2025-6218 baru masuk 9 Des 2025). | — |
| CQ8 tier prioritas | Belum | — | Iterasi berikutnya, setelah CQ1–CQ7 stabil |

Hasil lengkap ada di [hasil/hasil-cq-v0.1.md](hasil/hasil-cq-v0.1.md).

## 3. Temuan dari konstruksi

Temuan ini tidak terlihat dari profil data saja; baru muncul saat KG dibangun.

1. **Atribut waktu relasi STIX dari OpenCTI tidak dapat dipakai.** `created` dan
   `modified` pada 837 relasi bertanggal Maret 2026, yaitu waktu impor ke OpenCTI.
   Waktu bukti harus diambil dari `published` laporan. Ini menguatkan keputusan
   memakai *provenance* per laporan.
2. **Relasi yang sama muncul di beberapa laporan.** Ada 51 relasi yang dirujuk lebih
   dari satu laporan. Dengan satu graf bernama per laporan, relasi itu disimpan di
   setiap graf laporan yang memuatnya, sehingga kapan dan oleh siapa relasi dinyatakan
   tidak hilang.
3. **Nama vendor berbeda antarsumber.** CVE-2025-8088 mencatat vendor "win.rar GmbH",
   sedangkan CVE-2025-6218 dan KEV mencatat "RARLAB". Pencocokan aset karena itu
   memakai nama produk.
4. **UNKNOWN memang dibutuhkan.** WinRAR 7.13 (versi yang sudah diperbaiki) tetap
   berstatus UNKNOWN untuk CVE-2025-8088, karena rekaman CVE memakai
   `defaultStatus = unknown` dan tidak menyatakan versi 7.13 aman. Logika dua nilai
   akan salah menyimpulkan FALSE.
5. **Celah kosakata SEPSES**: CVSS v4.0 belum ada (lihat CQ2).

## 4. Pilihan desain v0.1 (perlu dikonfirmasi pembimbing)

| Pilihan | Keputusan v0.1 | Alternatif | Kaitan |
|---|---|---|---|
| Pola *provenance* | Graf bernama per laporan (IRI graf = IRI laporan) | RDF-star seperti ICS-SEC KG | K3 |
| Bahasa pemetaan | Python + rdflib | RML/CARML seperti `cat-json.rml` | K4 |
| Kosakata STIX | Pola ICS-SEC: kelas `cat:{tipe STIX}`, relasi sebagai *resource* (`cat:hasSourceRef`, `cat:hasTargetRef`, `cat:relationshipType`) | — | — |
| IRI CVE | Memakai IRI resource SEPSES (`http://w3id.org/sepses/resource/cve/CVE-…`), sehingga KG ini dapat digabung dengan SEPSES KG tanpa tautan tambahan | — | *Entity linking* |
| Namespace perluasan | `ext:` = `http://example.org/jejak-vp/ext#` (sementara) | Namespace resmi di bawah w3id.org/sepses bila disetujui | — |
| Triplestore | Fuseki TDB2 | Virtuoso, GraphDB | K3 (dukungan RDF-star) |
| Indikator/observable | v0.1: belum dipetakan. **Keputusan lingkup (opsi B, 11 Okt 2026):** indikator dimodelkan (kelas `cat:indicator`, relasi `indicates`, `valid_until`/`revoked`) dan dipakai pada CQ3b mulai v0.2; *observable* tidak dimodelkan | Dikeluarkan seluruhnya, atau dievaluasi kualitasnya | K14 |

## 5. Struktur folder

```text
06-prototipe-kg/
├── jalankan.sh                  # menjalankan seluruh alur (opsi --fuseki)
├── requirements.txt             # rdflib, pyshacl (dipasang di .venv/)
├── ontology/tbox-v0.1.ttl       # T-box: istilah SEPSES yang dipakai ulang + perluasan ext:
├── shapes/shapes-v0.1.ttl       # SHACL: syarat minimum agar CQ dapat dijawab
├── data/
│   ├── sampel-stix-v0.1.json    # sampel STIX hasil langkah 1 (+ .txt ringkasan dan SHA-256)
│   ├── aset-skenario.csv        # inventaris aset skenario (bukan data nyata)
│   └── organisasi-skenario.csv
├── pipeline/
│   ├── extract_sample.py        # 1. ambil sampel dari ekspor OpenCTI
│   ├── build_kg.py              # 2. pemetaan STIX + CVE List v5 + KEV + aset ke RDF (TriG)
│   ├── validate_kg.py           # 3. validasi SHACL
│   ├── run_queries.py           # 4. kueri CQ untuk 3 skenario t/W (rdflib atau Fuseki)
│   └── visualize.py             # 5. visualisasi A-box interaktif
├── queries/cq*.rq               # satu file SPARQL per CQ
├── output/                      # KG (TriG), statistik, laporan SHACL
├── hasil/                       # hasil kueri (Markdown) + visualisasi HTML
└── fuseki/                      # Dockerfile (rilis resmi Apache + cek SHA-512), config, compose
```

Graf bernama di dalam KG:

| Graf | Isi |
|---|---|
| `g:tbox` | T-box |
| `g:opencti-entities` | aktor, malware, teknik, sektor, negara (nama dan tipe; tidak bergantung waktu) |
| `res:report/{id}` (7 graf) | isi satu laporan: relasi STIX dan objek yang disebut (`ext:mentions`) |
| `g:report-metadata` | judul, tanggal terbit, pembuat, URL setiap laporan |
| `g:cve-sepses` | CVE, CVSS, CWE, produk terdampak (kosakata SEPSES; data CVE List v5) |
| `g:kev` | tanggal masuk KEV |
| `g:assets` | organisasi dan aset skenario |
| `g:derived-exposure` | hasil penilaian *exposure* dan aktivitas PROV-O yang menghasilkannya |

## 6. Cara menjalankan

Tanpa Docker (rdflib saja):

```bash
./jalankan.sh
```

Dengan Fuseki (memuat KG ke triplestore dan menjalankan kueri di sana):

```bash
./jalankan.sh --fuseki
```

Menghentikan Fuseki (data tetap tersimpan di volume Docker):

```bash
docker compose -f fuseki/docker-compose.yml down
```

## 7. Naskah demo untuk bimbingan (±10 menit)

Versi terbaru dan rinci (±15 menit, dengan rencana cadangan) ada di
`../05-log-keputusan/BIM-02-2026-10-16/04-naskah-demo.md`.

1. **CQ dan T-box.** Buka `ontology/tbox-v0.1.ttl`: tunjukkan bahwa setiap istilah
   `ext:` mencatat CQ yang membutuhkannya, dan istilah lain memakai ulang SEPSES/ICS-SEC.
2. **Database.** Buka http://localhost:3030 → dataset `/jejak` → tab *info*: 4.739 triple.
3. **CQ3 naif vs sah-waktu.** Salin `queries/cq3-konteks-ancaman-naif.rq` ke tab *query*
   (13 baris). Lalu jalankan `cq3-konteks-ancaman-per-t.rq` (7 baris pada t = 30 Sep
   2025). Bitter dan Earth Estries hilang karena laporannya terbit Oktober.
4. **CQ4 relevansi per laporan.** Jalankan `cq4-relevansi-sektor-negara.rq`: sektor
   Government untuk CVE-2025-8088 hanya didukung laporan Bitter, sehingga belum sah
   pada t = 30 Sep.
5. **Visualisasi.** Buka `hasil/visualisasi-abox-v0.1.html` dan ganti pilihan waktu
   keputusan: laporan, aktor, dan status KEV muncul atau hilang sesuai t.
6. **Yang belum terjawab.** Tunjukkan Bagian 2 (CQ2 dan CQ6 sebagian, CQ8 belum) dan
   Bagian 4 (keputusan yang diminta). Ini menjadi bahan iterasi v0.2.
