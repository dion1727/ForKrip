# Kriptofull

**Kriptofull** adalah aplikasi kriptografi berbasis web lokal untuk enkripsi dan dekripsi teks maupun dokumen `.txt`. Berjalan melalui browser tetapi diproses oleh server Python di komputer sendiri.

## Fitur

- Enkripsi/dekripsi **DES** dan **3DES** dengan implementasi Feistel/XOR sendiri atau library PyCryptodome.
- Enkripsi/dekripsi **AES-128/192/256** dengan PyCryptodome, termasuk mode GCM untuk autentikasi.
- Mode ECB dan CBC dengan padding PKCS#7; mode GCM khusus AES.
- Input teks dan file TXT, pratinjau, unduh hasil, verifikasi SHA-256, dan pengujian ulang.
- Format pertukaran ciphertext TXT **HEX**, **ZAR1**, **SLK1** (password turunan), dan **B64** (Base64 berlabel); mendukung format `.enc` biner versi terdahulu.
- Pengujian DES/3DES dan perbandingan implementasi sendiri versus library.
- Inspeksi ronde Feistel (16 ronde DES dan tiga tahap DES pada 3DES), dengan notasi XOR.
- Antarmuka berbahasa Indonesia dan contoh teks umum yang dapat diganti dengan dokumen pengguna.

> **Keamanan:** DES, 3DES, dan mode ECB tidak dianjurkan untuk melindungi data sensitif. Proyek ini menyediakan algoritma tersebut untuk kompatibilitas dan inspeksi proses. Untuk perlindungan data baru, lebih baik gunakan AES-GCM dengan password/kunci kuat. Proyek belum diaudit secara independen dan bukan pengganti aplikasi enkripsi teruji untuk kebutuhan berisiko tinggi.

## Menjalankan

Perlu Python 3.10 atau lebih baru (disarankan 3.12). Jalankan dari folder proyek:

```bash
python -m pip install -r requirements.txt
python app.py
```

Di Windows dapat memakai `py` sebagai pengganti `python`, atau menjalankan `INSTALL_LIBRARY.bat` lalu `JALANKAN_KRIPTOFULL.bat`.

Buka **http://127.0.0.1:5000**. Server hanya mendengarkan alamat loopback `127.0.0.1`, sehingga tidak langsung tersedia melalui jaringan. Hentikan server dengan **Ctrl+C**.

Jika port 5000 sedang digunakan, jalankan melalui PowerShell:

```powershell
$env:KRIPTOFULL_PORT="5001"
py app.py
```

`main.py` juga tersedia sebagai alternatif entry point. Program terminal: `python terminal_crypto.py`.

## Cara menggunakan

### Teks

1. Buka tab **Teks**, pilih algoritma, mode, dan implementasi.
2. Masukkan password atau kunci HEX, lalu masukkan plaintext.
3. Pilih format hasil, tekan **Enkripsi** dan gunakan **Unduh** jika perlu.
4. Untuk dekripsi, gunakan hasil enkripsi terakhir langsung atau tempel ciphertext dari file, masukkan kunci yang sama, lalu tekan **Dekripsi**. Pilih **Deteksi otomatis** untuk format yang didukung.

### File

- **Enkripsi File**: pilih file sendiri atau gunakan salah satu dokumen contoh netral, pilih format, enkripsi dan unduh `.txt` terenkripsi.
- **Dekripsi File**: unggah ciphertext, masukkan kunci yang sama dan gunakan deteksi format. Untuk memeriksa hasil secara byte, pilih juga berkas asli sebagai pembanding.
- Tombol **Teruskan ke Dekripsi** meneruskan hasil dan konfigurasi dari halaman Enkripsi File.

### Kunci dan format

- Kunci HEX bisa dimasukkan langsung (untuk DES 16 digit, 3DES 48 digit, AES menyesuaikan varian). Kunci teks yang tepat panjangnya bisa dipakai secara langsung; gunakan prefix `hex:` atau `text:` bila ingin memaksa interpretasi.
- Password dengan panjang selain ukuran kunci diproses menggunakan **PBKDF2-HMAC-SHA256**, salt acak, dan metadata SLK1. Password **3DES minimal 13 karakter** untuk proses enkripsi baru berbasis penurunan kunci.
- Ciphertext **HEX** menampung byte ciphertext dalam format heksadesimal; format **SLK1** mencakup parameter derivasi password serta HMAC; format **ZAR1** mendukung DES/3DES dalam CBC; format **B64** berisi label dan Base64. Ini adalah **format penyimpanan**, bukan algoritma tambahan.
- Ciphertext mentah yang tidak menyimpan algoritma/mode tidak memungkinkan aplikasi mengetahui kunci secara ajaib. Fitur deteksi otomatis dapat mencoba konfigurasi lazim menggunakan kunci yang diberikan; untuk data tanpa autentikasi, hasil yang tampak terbaca belum menjadi jaminan kriptografis.
- **Jangan menyimpan atau membagikan password bersama ciphertext**. Password hilang tidak dapat dipulihkan dari file terenkripsi.

## Struktur proyek

```text
Kriptofull/
├── app.py                 # Server HTTP lokal, endpoint API
├── main.py                # Entrypoint alternatif
├── des_own.py             # DES standar, 16 ronde Feistel dan XOR
├── des3_own.py            # 3DES EDE berbasis DES buatan sendiri
├── file_crypto.py         # Kunci, padding, mode, format ciphertext, AES
├── compare.py             # Pengujian kesesuaian dengan library
├── terminal_crypto.py     # Program kriptografi melalui terminal
├── static/                # HTML, CSS, JavaScript antarmuka
├── assets/                # Ikon aplikasi
├── contoh/                # Dokumen dummy publik, aman dibagikan
├── tests/                 # Unit/regression tests
├── requirements.txt
└── .gitignore
```

## Pengujian

```bash
python -m unittest discover -s tests -v
```

Sebagian tes membutuhkan paket `pycryptodome`; setelah `pip install -r requirements.txt`, pengujian perbandingan Crypto dapat dijalankan. Tidak perlu mengunggah dokumen pribadi untuk mencoba contoh.

## Kontribusi & publikasi GitHub

Repo ini mencakup kode, ikon, dan dokumen contoh; tidak menyertakan file pengguna maupun ciphertext dari pihak lain. Periksa kembali hak penggunaan ikon sebelum publikasi, dan tambahkan berkas LICENSE sesuai lisensi yang Anda pilih sebagai pemilik proyek.

Lihat `CONTRIBUTING.md` untuk panduan kontribusi serta `SECURITY.md` untuk batas keamanan.
