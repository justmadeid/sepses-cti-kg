# Ontologi (T-box) Prototipe v0.1

File: [`prototipe-kg/ontology/tbox-v0.1.ttl`](../prototipe-kg/ontology/tbox-v0.1.ttl).
Proposal: Subbab 4.4.1, Gambar 4.5 (T-box), Tabel 4.4 (*trace* istilah → CQ).

## Prinsip

1. **Pakai ulang sebelum membuat.** Kosakata SEPSES (`cve:`, `cvss:`, `cwe:`) dan pola
   ICS-SEC KG untuk STIX (`cat:`) dipakai apa adanya.
2. **Istilah baru hanya bila dibutuhkan CQ.** Setiap istilah `ext:` punya `rdfs:comment`
   yang dimulai dengan CQ yang membutuhkannya.
3. ***Provenance* per laporan memakai graf bernama** (pilihan sementara v0.1; alternatifnya
   RDF-star, keputusan K3).

## Namespace

| Prefiks | Namespace | Asal |
|---|---|---|
| `cve:` | `http://w3id.org/sepses/vocab/ref/cve#` | SEPSES |
| `cvss:` | `http://w3id.org/sepses/vocab/ref/cvss#` | SEPSES |
| `cwe:` | `http://w3id.org/sepses/vocab/ref/cwe#` | SEPSES |
| `cat:` | `http://w3id.org/sepses/vocab/ref/attack#` | SEPSES/ICS-SEC (di proposal ditulis `attack:`; namespace sama) |
| `prov:` | `http://www.w3.org/ns/prov#` | W3C PROV-O |
| `dcterm:` | `http://purl.org/dc/terms/` | DCMI |
| `ext:` | `http://example.org/jejak-vp/ext#` | Perluasan penelitian ini (namespace sementara) |
| `res:` | `http://example.org/jejak-vp/resource/` | IRI instans buatan penelitian ini |
| `cveres:` | `http://w3id.org/sepses/resource/cve/` | IRI instans CVE milik SEPSES (dipakai agar KG bisa digabung dengan SEPSES) |

## Kelas

| Kelas | Asal | Arti | CQ | Contoh instans |
|---|---|---|---|---|
| `cat:intrusion-set` | ICS-SEC | Aktor ancaman | CQ3, CQ4 | RomCom, Bitter |
| `cat:malware` | ICS-SEC | *Malware* | CQ3 | SnipBot, RustyClaw |
| `cat:attack-pattern` | ICS-SEC | Teknik ATT&CK | CQ3 | T1204 |
| `cat:relationship` | ICS-SEC | Relasi STIX sebagai *resource* | CQ3–CQ6 | "Bitter targets CVE-2025-8088" |
| `cat:indicator` | ICS-SEC | Pola IOC (dirancang; dipetakan mulai v0.2) | CQ3b, CQ5 | — |
| `cve:CVE` | SEPSES | Kerentanan | CQ1–CQ8 | CVE-2025-8088 |
| `cwe:CWE` | SEPSES | Kelemahan | CQ2 | CWE-35 |
| `cvss:CVSS3BaseMetric` | SEPSES | Skor CVSS v3 | CQ2 | 9,4 CRITICAL (CVE-2025-64446) |
| `ext:Report` | perluasan (⊑ `prov:Entity`) | Laporan CTI; IRI-nya sekaligus nama graf isinya | CQ4–CQ6 | Laporan Bitter 2025-10-23 |
| `ext:Sector` | perluasan (⊑ `cat:identity`) | Sektor sasaran | CQ4 | Government |
| `ext:Country` | perluasan | Negara sasaran | CQ4 | China, Pakistan |
| `ext:AffectedProduct` | perluasan | Satu entri produk terdampak pada rekaman CVE (vendor, produk, rentang versi) | CQ1 | win.rar GmbH / WinRAR, `0 .. <= 7.12` |
| `ext:Organization` | perluasan (⊑ `prov:Agent`) | Organisasi pengguna (skenario) | CQ4 | Pemerintah Daerah X |
| `ext:Asset` | perluasan | Perangkat lunak terpasang di aset | CQ1 | WS-PEMDA-01, WinRAR 7.10 |
| `ext:ExposureAssessment` | perluasan (⊑ `prov:Entity`) | Hasil pencocokan aset–CVE (TRUE/FALSE/UNKNOWN) dan alasannya | CQ1 | WS-PEMDA-01 × CVE-2025-8088 = TRUE |
| `prov:Agent` | PROV-O | Pembuat laporan | CQ6 | AlienVault |

## Relasi dan atribut utama

| Istilah | Dari → ke | CQ | Catatan |
|---|---|---|---|
| `cat:hasSourceRef`, `cat:hasTargetRef`, `cat:relationshipType` | relasi → objek / teks | CQ3–CQ6 | Pola ICS-SEC |
| `ext:mentions` | laporan → objek | CQ4, CQ6 | Isi `object_refs`; disimpan di graf laporan itu sendiri |
| `ext:published` | laporan → `xsd:dateTime` | CQ5, CQ6 | **Satu-satunya waktu bukti** |
| `prov:wasAttributedTo` | laporan → agen | CQ6 | Pembuat (konektor) |
| `ext:sourceUrl` | laporan → URL | CQ6 | Pulse OTX dan penerbit asli |
| `cve:hasCWE`, `cve:hasCVSS3BaseMetric` | CVE → CWE / CVSS | CQ2 | SEPSES |
| `ext:cvssV4BaseScore` | CVE → angka | CQ2 | Celah kosakata SEPSES (belum ada kelas CVSS v4) |
| `ext:kevDateAdded` | CVE → `xsd:date` | CQ7 | KEV pada t bila `kevDateAdded <= t` |
| `ext:hasAffectedProduct`, `ext:hasVersionRange` | CVE → produk → entri versi | CQ1 | Dari rekaman CVE List v5 |
| `ext:inSector`, `ext:inCountry` | organisasi → sektor / negara | CQ4 | IRI sama dengan sektor/negara OpenCTI |
| `ext:assessedAsset`, `ext:assessedCVE`, `ext:exposureStatus`, `ext:matchBasis` | penilaian → aset / CVE / status / alasan | CQ1 | Dihasilkan `build_kg.py` |
| `ext:validFrom`, `ext:validUntil`, `ext:revoked` | *indicator* → waktu / boolean | CQ3b, CQ5 | Dirancang; dipetakan mulai v0.2 (K14, K16) |

## Kenapa graf bernama per laporan?

Satu pernyataan seperti "RomCom targets CVE-2025-8088" bisa dimuat beberapa laporan
dengan tanggal berbeda. Di seluruh korpus, 11,5% relasi "X targets CVE" dimuat lebih dari
satu laporan. Bila setiap laporan punya graf sendiri, pertanyaan "menurut laporan yang
sudah terbit pada t, siapa yang menargetkan CVE ini?" cukup dijawab dengan memilih graf
laporan yang tanggalnya ≤ t:

```sparql
GRAPH ?lap { ?r cat:hasTargetRef ?c ; cat:relationshipType "targets" ; cat:hasSourceRef ?x . }
GRAPH g:report-metadata { ?lap ext:published ?terbit . }
FILTER(?terbit <= ?t)
```

Alternatifnya RDF-star (pola ICS-SEC): setiap triple diberi anotasi laporan. Kedua pola
dapat menjawab CQ yang sama; pilihannya menunggu keputusan pembimbing (K3).

## Yang belum ada di T-box v0.1

- CAPEC (CQ2) belum dimuat karena butuh lapisan SEPSES CWE → CAPEC.
- Tier prioritas (CQ8) belum dimodelkan.
- *Provenance* dua tingkat (penerbit asli, K15) baru tersedia sebagai URL, belum sebagai
  `prov:wasDerivedFrom`.
