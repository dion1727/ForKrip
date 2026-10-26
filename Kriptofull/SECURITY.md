# Catatan keamanan

Kriptofull adalah aplikasi lokal untuk enkripsi file teks, kompatibilitas algoritma lama, dan eksplorasi Feistel. DES, 3DES, dan ECB memiliki kelemahan historis dan tidak cocok untuk data sensitif. Gunakan algoritma modern seperti AES-GCM dengan kunci kuat untuk kebutuhan yang memerlukan kerahasiaan dan autentikasi.

Server HTTP terikat ke `127.0.0.1` dan tidak dimaksudkan untuk dipasang sebagai layanan publik. **Jangan melakukan port forwarding atau mempublikasikan server ini ke internet** tanpa autentikasi, TLS, perlindungan input, audit, dan hardening tambahan. Jangan unggah dokumen rahasia ke layanan/komputer yang tidak dipercaya.

Format HEX/ZAR1 lama tidak menyediakan autentikasi terstandar. Hasil dekripsi yang tampak sebagai teks belum cukup untuk membuktikan integritas. SLK1 memakai HMAC dan salt, tetapi format kustom ini belum diaudit. Password harus disimpan secara aman oleh pengguna dan tidak dikomit ke repo.

Jika menemukan kerentanan, laporkan secara privat kepada pemilik repo sebelum mempublikasikan detail eksploitasi.
