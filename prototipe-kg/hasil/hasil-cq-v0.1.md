# Hasil kueri CQ, prototipe KG v0.1

Dihasilkan otomatis oleh `pipeline/run_queries.py` dari rdflib (output/kg-sampel-v0.1.trig). Jangan diedit manual.

## cq1-exposure-aset.rq

> CQ1. CVE apa yang memengaruhi aset organisasi, dengan status TRUE/FALSE/UNKNOWN dan dasar pencocokannya?

**Skenario: tanpa waktu** (8 baris)

| aset | produk | versi | cve | status | dasar |
|---|---|---|---|---|---|
| WAF-PEMDA-01 (Web application firewall portal layanan) | FortiWeb | 7.4.5 | CVE-2025-64446 | TRUE | produk 'Fortinet FortiWeb': versi 7.4.5 di dalam rentang 7.4.0 .. <= 7.4.9 (affected) |
| WAF-PEMDA-02 (Web application firewall cadangan) | FortiWeb | 7.4.10 | CVE-2025-64446 | FALSE | produk 'Fortinet FortiWeb': versi 7.4.10 tidak tercantum; defaultStatus = unaffected |
| WS-PEMDA-01 (Workstation staf keuangan) | WinRAR | 7.10 | CVE-2025-6218 | UNKNOWN | produk 'RARLAB WinRAR': versi 7.10 tidak tercantum; defaultStatus = unknown |
| WS-PEMDA-01 (Workstation staf keuangan) | WinRAR | 7.10 | CVE-2025-8088 | TRUE | produk 'win.rar GmbH WinRAR': versi 7.10 di dalam rentang 0 .. <= 7.12 (affected) |
| WS-PEMDA-02 (Workstation staf umum) | WinRAR | 7.11 | CVE-2025-6218 | TRUE | produk 'RARLAB WinRAR': versi 7.11 sama dengan versi tercatat '7.11 (64-bit)' (affected) |
| WS-PEMDA-02 (Workstation staf umum) | WinRAR | 7.11 | CVE-2025-8088 | TRUE | produk 'win.rar GmbH WinRAR': versi 7.11 di dalam rentang 0 .. <= 7.12 (affected) |
| WS-PEMDA-03 (Workstation admin) | WinRAR | 7.13 | CVE-2025-6218 | UNKNOWN | produk 'RARLAB WinRAR': versi 7.13 tidak tercantum; defaultStatus = unknown |
| WS-PEMDA-03 (Workstation admin) | WinRAR | 7.13 | CVE-2025-8088 | UNKNOWN | produk 'win.rar GmbH WinRAR': versi 7.13 tidak tercantum; defaultStatus = unknown |

## cq2-keparahan.rq

> CQ2. Berapa CVSS dan CWE setiap CVE yang (mungkin) memengaruhi aset? Sumber: graf cve-sepses (kosakata SEPSES; data dari CVE List v5).

**Skenario: tanpa waktu** (3 baris)

| cve | cvss3 | keparahan3 | cvss4 | cwe_list |
|---|---|---|---|---|
| CVE-2025-6218 | 7.8 | HIGH |  | CWE-22 |
| CVE-2025-64446 | 9.4 | CRITICAL |  | CWE-23 |
| CVE-2025-8088 |  |  | 8.4 | CWE-35 |

## cq3-konteks-ancaman-naif.rq

> CQ3 (versi NAIF, tanpa waktu). Aktor, malware, atau teknik mana yang dinyatakan menargetkan CVE ini? Semua laporan dipakai, termasuk yang terbit sesudah t. Dipakai sebagai pembanding (baseline B1 integrasi naif).

**Skenario: tanpa waktu** (13 baris)

| cve | jenis | nama | jumlah_laporan |
|---|---|---|---|
| CVE-2025-8088 | intrusion-set | Bitter | 1 |
| CVE-2025-8088 | intrusion-set | Earth Estries | 1 |
| CVE-2025-8088 | intrusion-set | RomCom | 2 |
| CVE-2025-8088 | intrusion-set | RomCom, Paper Werewolf | 1 |
| CVE-2025-8088 | malware | C# backdoor | 1 |
| CVE-2025-8088 | malware | Mythic | 1 |
| CVE-2025-8088 | malware | Mythic C2 agent | 1 |
| CVE-2025-8088 | malware | POISONPLUG.SHADOW | 1 |
| CVE-2025-8088 | malware | Romcom.49869.SL | 1 |
| CVE-2025-8088 | malware | RustyClaw | 2 |
| CVE-2025-8088 | malware | ShadowPad - S0596 | 1 |
| CVE-2025-8088 | malware | Snappybee | 1 |
| CVE-2025-8088 | malware | SnipBot | 2 |

## cq3-konteks-ancaman-per-t.rq

> CQ3 + CQ5 (versi SAH-WAKTU). Aktor/malware mana yang menargetkan CVE ini menurut laporan yang SUDAH terbit pada waktu keputusan t dan masih di dalam jendela kebaruan W (tMulai = t - W)? Ganti baris VALUES untuk skenario lain.

**Skenario: t = 30 Sep 2025, W = 180** (7 baris)

| cve | jenis | nama | jumlah_laporan | laporan_terbaru |
|---|---|---|---|---|
| CVE-2025-8088 | intrusion-set | RomCom | 2 | 2025-09-15 |
| CVE-2025-8088 | intrusion-set | RomCom, Paper Werewolf | 1 | 2025-08-25 |
| CVE-2025-8088 | malware | Mythic | 1 | 2025-08-11 |
| CVE-2025-8088 | malware | Mythic C2 agent | 1 | 2025-09-15 |
| CVE-2025-8088 | malware | Romcom.49869.SL | 1 | 2025-08-25 |
| CVE-2025-8088 | malware | RustyClaw | 2 | 2025-09-15 |
| CVE-2025-8088 | malware | SnipBot | 2 | 2025-09-15 |

**Skenario: t = 31 Des 2025, W = 180** (13 baris)

| cve | jenis | nama | jumlah_laporan | laporan_terbaru |
|---|---|---|---|---|
| CVE-2025-8088 | intrusion-set | Bitter | 1 | 2025-10-23 |
| CVE-2025-8088 | intrusion-set | Earth Estries | 1 | 2025-10-28 |
| CVE-2025-8088 | intrusion-set | RomCom | 2 | 2025-09-15 |
| CVE-2025-8088 | intrusion-set | RomCom, Paper Werewolf | 1 | 2025-08-25 |
| CVE-2025-8088 | malware | C# backdoor | 1 | 2025-10-23 |
| CVE-2025-8088 | malware | Mythic | 1 | 2025-08-11 |
| CVE-2025-8088 | malware | Mythic C2 agent | 1 | 2025-09-15 |
| CVE-2025-8088 | malware | POISONPLUG.SHADOW | 1 | 2025-10-28 |
| CVE-2025-8088 | malware | Romcom.49869.SL | 1 | 2025-08-25 |
| CVE-2025-8088 | malware | RustyClaw | 2 | 2025-09-15 |
| CVE-2025-8088 | malware | ShadowPad - S0596 | 1 | 2025-10-28 |
| CVE-2025-8088 | malware | Snappybee | 1 | 2025-10-28 |
| CVE-2025-8088 | malware | SnipBot | 2 | 2025-09-15 |

**Skenario: t = 31 Des 2025, W = 90** (6 baris)

| cve | jenis | nama | jumlah_laporan | laporan_terbaru |
|---|---|---|---|---|
| CVE-2025-8088 | intrusion-set | Bitter | 1 | 2025-10-23 |
| CVE-2025-8088 | intrusion-set | Earth Estries | 1 | 2025-10-28 |
| CVE-2025-8088 | malware | C# backdoor | 1 | 2025-10-23 |
| CVE-2025-8088 | malware | POISONPLUG.SHADOW | 1 | 2025-10-28 |
| CVE-2025-8088 | malware | ShadowPad - S0596 | 1 | 2025-10-28 |
| CVE-2025-8088 | malware | Snappybee | 1 | 2025-10-28 |

## cq4-relevansi-sektor-negara.rq

> CQ4. Adakah laporan sah-waktu yang mengaitkan CVE dengan SEKTOR atau NEGARA organisasi? Relevansi dibaca PER LAPORAN: CVE dan sektor/negara harus disebut di dalam graf laporan yang sama (bukan lewat rantai relasi transitif).

**Skenario: t = 30 Sep 2025, W = 180** (2 baris)

| cve | dimensi | nilai | laporan | terbit | sah_pada_t |
|---|---|---|---|---|---|
| CVE-2025-6218 | sektor | Government | Paper Werewolf targets Russia with WinRAR zero-day vulnerability | 2025-08-20 | ya |
| CVE-2025-8088 | sektor | Government | Bitter (APT-Q-37) uses diverse means to deliver new backdoor components | 2025-10-23 | tidak |

**Skenario: t = 31 Des 2025, W = 180** (2 baris)

| cve | dimensi | nilai | laporan | terbit | sah_pada_t |
|---|---|---|---|---|---|
| CVE-2025-6218 | sektor | Government | Paper Werewolf targets Russia with WinRAR zero-day vulnerability | 2025-08-20 | ya |
| CVE-2025-8088 | sektor | Government | Bitter (APT-Q-37) uses diverse means to deliver new backdoor components | 2025-10-23 | ya |

**Skenario: t = 31 Des 2025, W = 90** (2 baris)

| cve | dimensi | nilai | laporan | terbit | sah_pada_t |
|---|---|---|---|---|---|
| CVE-2025-6218 | sektor | Government | Paper Werewolf targets Russia with WinRAR zero-day vulnerability | 2025-08-20 | tidak |
| CVE-2025-8088 | sektor | Government | Bitter (APT-Q-37) uses diverse means to deliver new backdoor components | 2025-10-23 | ya |

## cq5-status-bukti-per-t.rq

> CQ5. Per waktu keputusan t, laporan mana yang BERLAKU, BELUM TERBIT (bocor dari masa depan bila dipakai), atau USANG (lebih tua dari jendela W)?

**Skenario: t = 30 Sep 2025, W = 180** (8 baris)

| cve | terbit | laporan | status_bukti |
|---|---|---|---|
| CVE-2025-6218 | 2025-08-20 | Paper Werewolf targets Russia with WinRAR zero-day vulnerability | BERLAKU |
| CVE-2025-6218 | 2025-08-25 | WinRAR Directory Traversal & NTFS ADS Vulnerabilities (CVE-2025-6218 & CVE-2025-8088) | BERLAKU |
| CVE-2025-64446 | 2025-11-25 | Russian RomCom Utilizing SocGholish to Deliver Mythic Agent to U.S. Companies Supporting Ukraine | BELUM TERBIT |
| CVE-2025-8088 | 2025-08-11 | Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability | BERLAKU |
| CVE-2025-8088 | 2025-08-25 | WinRAR Directory Traversal & NTFS ADS Vulnerabilities (CVE-2025-6218 & CVE-2025-8088) | BERLAKU |
| CVE-2025-8088 | 2025-09-15 | August Vulnerabilities of Note | BERLAKU |
| CVE-2025-8088 | 2025-10-23 | Bitter (APT-Q-37) uses diverse means to deliver new backdoor components | BELUM TERBIT |
| CVE-2025-8088 | 2025-10-28 | Earth Entries alive and kicking | BELUM TERBIT |

**Skenario: t = 31 Des 2025, W = 180** (8 baris)

| cve | terbit | laporan | status_bukti |
|---|---|---|---|
| CVE-2025-6218 | 2025-08-20 | Paper Werewolf targets Russia with WinRAR zero-day vulnerability | BERLAKU |
| CVE-2025-6218 | 2025-08-25 | WinRAR Directory Traversal & NTFS ADS Vulnerabilities (CVE-2025-6218 & CVE-2025-8088) | BERLAKU |
| CVE-2025-64446 | 2025-11-25 | Russian RomCom Utilizing SocGholish to Deliver Mythic Agent to U.S. Companies Supporting Ukraine | BERLAKU |
| CVE-2025-8088 | 2025-08-11 | Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability | BERLAKU |
| CVE-2025-8088 | 2025-08-25 | WinRAR Directory Traversal & NTFS ADS Vulnerabilities (CVE-2025-6218 & CVE-2025-8088) | BERLAKU |
| CVE-2025-8088 | 2025-09-15 | August Vulnerabilities of Note | BERLAKU |
| CVE-2025-8088 | 2025-10-23 | Bitter (APT-Q-37) uses diverse means to deliver new backdoor components | BERLAKU |
| CVE-2025-8088 | 2025-10-28 | Earth Entries alive and kicking | BERLAKU |

**Skenario: t = 31 Des 2025, W = 90** (8 baris)

| cve | terbit | laporan | status_bukti |
|---|---|---|---|
| CVE-2025-6218 | 2025-08-20 | Paper Werewolf targets Russia with WinRAR zero-day vulnerability | USANG |
| CVE-2025-6218 | 2025-08-25 | WinRAR Directory Traversal & NTFS ADS Vulnerabilities (CVE-2025-6218 & CVE-2025-8088) | USANG |
| CVE-2025-64446 | 2025-11-25 | Russian RomCom Utilizing SocGholish to Deliver Mythic Agent to U.S. Companies Supporting Ukraine | BERLAKU |
| CVE-2025-8088 | 2025-08-11 | Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability | USANG |
| CVE-2025-8088 | 2025-08-25 | WinRAR Directory Traversal & NTFS ADS Vulnerabilities (CVE-2025-6218 & CVE-2025-8088) | USANG |
| CVE-2025-8088 | 2025-09-15 | August Vulnerabilities of Note | USANG |
| CVE-2025-8088 | 2025-10-23 | Bitter (APT-Q-37) uses diverse means to deliver new backdoor components | BERLAKU |
| CVE-2025-8088 | 2025-10-28 | Earth Entries alive and kicking | BERLAKU |

## cq6-provenance.rq

> CQ6. Laporan, pembuat, waktu, dan referensi apa yang mendukung pernyataan "<aktor> menargetkan <CVE>"?

**Skenario: tanpa waktu** (5 baris)

| aktor | cve | laporan | terbit | pembuat | pulse_otx | sumber_asli |
|---|---|---|---|---|---|---|
| RomCom | CVE-2025-8088 | Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability | 2025-08-11 | AlienVault | https://otx.alienvault.com/pulse/689a04b1cf818643f79c1bd3 | https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability |
| RomCom, Paper Werewolf | CVE-2025-8088 | WinRAR Directory Traversal & NTFS ADS Vulnerabilities (CVE-2025-6218 & CVE-2025-8088) | 2025-08-25 | AlienVault | https://otx.alienvault.com/pulse/68aca47585bdf707090e4290 | https://www.seqrite.com/blog/winrar-directory-traversal-ntfs-ads-vulnerabilities-cve-2025-6218-cve-2025-8088/ |
| RomCom | CVE-2025-8088 | August Vulnerabilities of Note | 2025-09-15 | AlienVault | https://otx.alienvault.com/pulse/68c8542d707c703692b65d8f | https://www.recordedfuture.com/blog/august-2025-cve-landscape |
| Bitter | CVE-2025-8088 | Bitter (APT-Q-37) uses diverse means to deliver new backdoor components | 2025-10-23 | AlienVault | https://otx.alienvault.com/pulse/68f9e25d901d09154f09b282 | https://ti.qianxin.com/blog/articles/bitter-uses-diverse-means-to-deliver-new-backdoor-components-en |
| Earth Estries | CVE-2025-8088 | Earth Entries alive and kicking | 2025-10-28 | AlienVault | https://otx.alienvault.com/pulse/690032a10721de5f05a42a01 | https://bartblaze.blogspot.com/2025/10/earth-estries-alive-and-kicking.html |

## cq7-status-kev-per-t.rq

> CQ7. Apakah CVE yang (mungkin) memengaruhi aset berstatus KEV pada waktu t, dan sejak kapan?

**Skenario: t = 30 Sep 2025, W = 180** (3 baris)

| cve | kev_sejak | status_kev_pada_t | ransomware |
|---|---|---|---|
| CVE-2025-6218 | 2025-12-09 | belum KEV | Unknown |
| CVE-2025-64446 | 2025-11-14 | belum KEV | Unknown |
| CVE-2025-8088 | 2025-08-12 | KEV | Known |

**Skenario: t = 31 Des 2025, W = 180** (3 baris)

| cve | kev_sejak | status_kev_pada_t | ransomware |
|---|---|---|---|
| CVE-2025-6218 | 2025-12-09 | KEV | Unknown |
| CVE-2025-64446 | 2025-11-14 | KEV | Unknown |
| CVE-2025-8088 | 2025-08-12 | KEV | Known |

**Skenario: t = 31 Des 2025, W = 90** (3 baris)

| cve | kev_sejak | status_kev_pada_t | ransomware |
|---|---|---|---|
| CVE-2025-6218 | 2025-12-09 | KEV | Unknown |
| CVE-2025-64446 | 2025-11-14 | KEV | Unknown |
| CVE-2025-8088 | 2025-08-12 | KEV | Known |
