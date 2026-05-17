# SecureVault - Password Manager

SecureVault adalah aplikasi Password Manager berbasis desktop yang dirancang dengan Arsitektur Zero-Knowledge. Aplikasi ini dibangun menggunakan Python, antarmuka Tkinter, dan penyimpanan database MySQL dengan tingkat keamanan tinggi menggunakan algoritma kriptografi modern.

---

## Teknologi & Tools
- Bahasa: Python 3.10+
- Antarmuka (GUI): Tkinter + ttk (Modern Theme)
- Database: MySQL (via XAMPP / Laragon)
- Library Kriptografi: cryptography
- Driver Database: mysql-connector-python

---

## Algoritma Kriptografi yang Digunakan
1. AES-256-GCM
   Digunakan untuk proses enkripsi dan dekripsi password yang disimpan. Menjamin kerahasiaan dan integritas data menggunakan auth_tag.
2. PBKDF2-HMAC-SHA256
   Digunakan sebagai Key Derivation Function (KDF) untuk menurunkan Master Key dengan 390.000 iterasi ditambah Salt acak, guna memperlambat dan mencegah serangan Brute-force maupun Dictionary Attack.
3. SHA-256
   Digunakan untuk men-hash Token Recovery satu kali pakai yang memiliki batas waktu kadaluarsa.

---

## Struktur File & Direktori

| Nama File | Deskripsi / Fungsi Utama |
|---|---|
| main.py | Mengatur seluruh antarmuka pengguna (GUI) dan alur jalannya aplikasi. |
| crypto.py | Modul yang berisi seluruh logika algoritma kriptografi (Enkripsi, Hashing, Token). |
| database.py | Mengelola koneksi dan operasi CRUD ke database MySQL. |
| db_password_manager.sql | Skema database yang diekspor, berisi struktur tabel user, password_entries, dan audit_log. |
| requirements.txt | Daftar library eksternal yang dibutuhkan agar aplikasi dapat berjalan tanpa error. |

---

## Panduan Instalasi & Menjalankan Aplikasi

Jika Anda ingin menjalankan aplikasi ini di komputer lain, silakan ikuti langkah-langkah berikut:

### 1. Persiapan Database
1. Nyalakan layanan Apache dan MySQL melalui aplikasi XAMPP/Laragon.
2. Buka browser dan akses halaman http://localhost/phpmyadmin/
3. Buat database baru dengan nama harus persis: db_password_manager
4. Pilih tab Import, masukkan file db_password_manager.sql, dan klik Go/Kirim.

### 2. Persiapan Python
1. Pastikan komputer Anda sudah terinstal Python versi 3.10 ke atas.
2. Buka Terminal/CMD di dalam folder proyek ini.
3. Instal semua library yang dibutuhkan dengan perintah:
   ```bash
   pip install -r requirements.txt
   ```

### 3. Menjalankan Aplikasi
Setelah database dan library siap, jalankan aplikasi menggunakan perintah berikut:
```bash
python main.py
```

---

## Nama Anggota (Kelompok 2)
- Syaikhah Azzahra Nasir | 241712037
- William Tanu Wijaya | 241712036
- Habil Rizky Tazir | 241712030
