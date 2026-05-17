# SecureVault_PraktikumKripto_Kelompok2

Aplikasi password manager berbasis desktop yang dibangun menggunakan 
Python, Tkinter, dan MySQL dengan enkripsi AES-256-GCM.

## Teknologi
- Python 3.10+
- Tkinter (GUI)
- MySQL + phpMyAdmin (Database)
- Library: `cryptography`, `mysql-connector-python`

## Algoritma Kriptografi
- AES-256-GCM — enkripsi password
- PBKDF2-HMAC-SHA256 — derivasi Master Key (390.000 iterasi)
- SHA-256 — hashing token recovery

## Struktur File
| File | Fungsi |
|------|--------|
| `crypto.py` | Modul kriptografi (enkripsi, hashing, token) |
| `database.py` | Koneksi dan operasi CRUD ke MySQL |
| `main.py` | Antarmuka pengguna Tkinter + integrasi |
| `securevault_schema.sql` | Skema database MySQL |

## Instalasi
pip install cryptography mysql-connector-python

## Cara Menjalankan
1. Jalankan MySQL (XAMPP/Laragon)
2. Import `securevault_schema.sql` ke phpMyAdmin
3. Jalankan `python main.py`

## Kelompok 2
- Syaikhah Azzahra Nasir | 241712037
- William Tanu Wijaya    | 241712036
- Habil Rizky Tazir      | 241712030
