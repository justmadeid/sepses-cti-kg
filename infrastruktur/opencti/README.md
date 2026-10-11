# Arsip Infrastruktur Akuisisi Data OpenCTI

Salinan konfigurasi instans OpenCTI peneliti, disimpan sebagai artefak
provenance dan reproduksibilitas data D1. Tanggal salin: 9 Oktober 2026.

| Berkas | Isi |
|---|---|
| `docker-compose.yml` | Salinan dari `~/Project/OpenCTI/docker-compose.yml`. Kredensial memakai variabel `${...}` dan tidak ada nilai rahasia di dalamnya. SHA-256: `eea2b5c9ca7f3ad7dd9f92411d769cb30d4730a03f742bac645660c40e627e24` |
| `image-manifest.csv` | Image, tag, platform, image ID, dan tanggal build setiap container (dari `docker compose images`) |
| `rabbitmq.conf` | Salinan dari `~/Project/OpenCTI/rabbitmq.conf` (batas ukuran pesan dan *timeout*; disalin 11 Oktober 2026) |
| `.env.example` | Ditulis ulang 11 Oktober 2026: semua nilai rahasia diganti `ChangeMe`. `.env.example` asli **tidak** disalin karena memuat nilai token yang tampak nyata |
| `scripts/split_stix_bundle.py` | Salinan dari `~/Project/OpenCTI/scripts/`. Membentuk `data/raw/alienvault/alienvault-split/` dari ekspor penuh `alienvault.json` (lihat bagian alur data) |

## Alur data D1

1. Konektor AlienVault OTX di OpenCTI mengimpor pulse sejak 1 Januari 2025.
2. Seluruh isi diekspor sebagai satu bundle STIX 2.1: `data/raw/alienvault/alienvault.json`
   (573.967 objek; SHA-256 `ce71f16c…` tercatat di `manifest.json`).
3. `scripts/split_stix_bundle.py alienvault.json alienvault-split --target-mib 48`:
   - membuang **43.888 relasi rusak** (relasi yang `source_ref` atau `target_ref`-nya
     tidak ada di bundle), sekaligus menghapus rujukannya dari `object_refs` laporan;
   - untuk setiap laporan (urut `published`) mengambil penutupan dependensinya
     (semua objek yang dirujuk, secara rekursif). Objek yang tidak dirujuk laporan mana
     pun tidak terbawa;
   - menggabungkan laporan ke potongan ≤ 48 MiB (8 file) dan menulis `manifest.json`.
4. Semua skrip penelitian membaca 8 file potongan tersebut (530.079 objek unik).

## Nilai konfigurasi non-rahasia dari `.env`

Hanya baris berikut yang dibaca dari `.env`:

- `OPENCTI_VERSION=latest`
- `ALIENVAULT_PULSE_START_TIMESTAMP=2025-01-01T00:00:00`
- `ALIENVAULT_DURATION_PERIOD=PT6H`
- `ALIENVAULT_TLP=White`

## Versi

Versi pycti di image `worker` dan `connector-alienvault` adalah `7.260824.0`.
Image platform tidak memuat label versi. Konfirmasi versinya lewat menu
**Settings > About** di UI OpenCTI.

## Catatan untuk tesis

- Patok `OPENCTI_VERSION` ke versi tertentu sebelum akuisisi data eksperimen.
  Jangan memakai `latest`.
- Catat digest image saat akuisisi dengan:
  ```bash
  docker compose images --format json
  ```
- Jangan pernah menyalin `.env` ke repositori penelitian.
