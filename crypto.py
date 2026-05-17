
#  Algoritma yang dipakai:
#   - PBKDF2-HMAC-SHA256  → mengolah Master Key jadi kunci AES
#   - AES-256-GCM         → mengenkripsi password akun
#   - os.urandom()        → pembuat bilangan acak kriptografis
#   - secrets.token_bytes → pembuat token recovery yang aman

import os
import hashlib
import secrets
import hmac
from datetime import datetime, timedelta

# Library kriptografi pihak ketiga — install dulu:
# pip install cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ─────────────────────────────────────────────────────────────
#  BAGIAN 1: SALT
#  Salt = data acak yang dicampur ke Master Key sebelum di-hash.
#  Tujuannya: dua user dengan password sama tetap punya hash
#  yang berbeda, sehingga database tidak bisa diserang sekaligus.
# ─────────────────────────────────────────────────────────────

def generate_salt(panjang_byte: int = 32) -> bytes:
    """
    Buat salt acak yang aman secara kriptografis.

    Hasilnya dikirim ke Habil untuk disimpan di kolom:
        tabel user → kolom salt  (tipe BLOB)

    Parameter:
        panjang_byte : berapa byte salt yang dibuat (default 32)

    Mengembalikan:
        bytes — data acak sejumlah panjang_byte
    """
    return os.urandom(panjang_byte)


# ─────────────────────────────────────────────────────────────
#  BAGIAN 2: HASHING MASTER KEY DENGAN PBKDF2
#
#  PBKDF2 = Password-Based Key Derivation Function 2
#  Cara kerjanya:
#    1. Ambil Master Key yang diketik user
#    2. Campur dengan salt unik milik user
#    3. Hash hasilnya 390.000 kali berulang (standar NIST 2023)
#    4. Hasilnya: kunci 32 byte (256 bit) — siap dipakai AES-256
#
#  Kenapa diulang 390.000 kali? Supaya hacker butuh waktu sangat
#  lama untuk menebak Master Key meski punya komputer cepat.
# ─────────────────────────────────────────────────────────────

def hash_master_key(master_key: str, salt: bytes) -> bytes:
    """
    Ubah Master Key (teks) menjadi kunci AES 256-bit yang kuat
    menggunakan algoritma PBKDF2-HMAC-SHA256.

    Hasilnya dipakai untuk 2 tujuan:
      1. Disimpan ke DB sebagai bukti kepemilikan vault
         → tabel user → kolom master_hash  (tipe BLOB)
      2. Dipakai sebagai kunci aktif untuk enkripsi/dekripsi
         (TIDAK disimpan ke database — hanya hidup di RAM)

    Parameter:
        master_key : string Master Key yang diketik user
        salt       : bytes salt unik dari generate_salt()

    Mengembalikan:
        bytes — kunci 32 byte (256 bit) untuk AES-256-GCM
    """
    kunci = hashlib.pbkdf2_hmac(
        hash_name  = 'sha256',                  # algoritma hash
        password   = master_key.encode('utf-8'),# ubah teks → bytes
        salt       = salt,                       # bumbu unik user
        iterations = 390_000,                   # ulang 390.000 kali
        dklen      = 32                         # panjang output: 32 byte
    )
    return kunci


# ─────────────────────────────────────────────────────────────
#  BAGIAN 3: VERIFIKASI MASTER KEY SAAT LOGIN
#
#  Cara verifikasi yang BENAR:
#    1. Ambil salt milik user dari database (via Habil)
#    2. Hash ulang input user dengan salt yang sama
#    3. Bandingkan hasilnya dengan hash yang tersimpan di DB
#    4. Jika sama → login berhasil, jika beda → tolak
#
#  JANGAN membandingkan teks langsung — kita tidak menyimpan
#  password asli di mana pun!
# ─────────────────────────────────────────────────────────────

def verifikasi_master_key(
    input_user   : str,
    hash_tersimpan: bytes,
    salt         : bytes
) -> bool:
    """
    Cek apakah Master Key yang diketik user cocok dengan
    yang terdaftar di database.

    Dipanggil oleh William saat user klik tombol "Login".

    Parameter:
        input_user     : string yang diketik user di kolom Master Key
        hash_tersimpan : bytes hash dari DB (kolom user.master_hash)
        salt           : bytes salt dari DB (kolom user.salt)

    Mengembalikan:
        True  → Master Key benar, buka vault
        False → Master Key salah, tampilkan error
    """
    hash_input = hash_master_key(input_user, salt)

    # hmac.compare_digest lebih aman dari (==) biasa
    # karena mencegah serangan timing attack
    return hmac.compare_digest(hash_input, hash_tersimpan)


# ─────────────────────────────────────────────────────────────
#  BAGIAN 4: ENKRIPSI PASSWORD AKUN — AES-256-GCM
#
#  AES-256-GCM lebih canggih dari AES-CBC karena selain
#  mengenkripsi, dia juga membuat "tanda tangan" (auth_tag)
#  yang membuktikan data tidak dirusak oleh siapa pun.
#
#  Tiga hal yang dihasilkan fungsi ini:
#    - password_enc : isi password yang sudah dikunci (ciphertext)
#    - iv           : bilangan acak sekali pakai (nonce)
#    - auth_tag     : tanda tangan keaslian data
#
#  Ketiganya disimpan terpisah di DB oleh Habil:
#    → password_entries.password_enc  (BLOB)
#    → password_entries.iv            (BLOB)
#    → password_entries.auth_tag      (BLOB — sudah ada di ciphertext GCM)
# ─────────────────────────────────────────────────────────────

def enkripsi_password(teks_asli: str, kunci_aes: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Enkripsi password akun menggunakan AES-256-GCM.

    Dipanggil William saat user klik "Simpan" di form tambah password.
    Hasilnya (3 nilai) dikirim ke Habil untuk disimpan ke DB.

    Parameter:
        teks_asli : password akun yang diketik user (contoh: "p@$$w0rd!")
        kunci_aes : bytes kunci AES 32-bit dari hash_master_key()

    Mengembalikan tuple (3 nilai):
        (ciphertext_bytes, iv_bytes, auth_tag_bytes)
        → Habil simpan ke: password_enc, iv, auth_tag
    """
    # IV (Initialization Vector) = angka acak sekali pakai
    # Harus berbeda setiap kali enkripsi! (12 byte = standar GCM)
    iv = os.urandom(12)

    # Buat objek enkripsi AES-GCM dengan kunci 32 byte
    mesin_aes = AESGCM(kunci_aes)

    # Enkripsi — hasilnya: ciphertext + auth_tag (digabung otomatis)
    hasil_gabung = mesin_aes.encrypt(iv, teks_asli.encode('utf-8'), None)

    # Pisahkan ciphertext (semua kecuali 16 byte terakhir)
    # dan auth_tag (16 byte terakhir) — sesuai standar GCM
    ciphertext = hasil_gabung[:-16]
    auth_tag   = hasil_gabung[-16:]

    return ciphertext, iv, auth_tag


def dekripsi_password(
    ciphertext : bytes,
    iv         : bytes,
    auth_tag   : bytes,
    kunci_aes  : bytes
) -> str:
    """
    Dekripsi password yang tersimpan di database kembali ke teks asli.

    Dipanggil William saat user klik "Lihat" atau "Salin".
    Data (ciphertext, iv, auth_tag) diambil dari DB oleh Habil,
    lalu dioper ke fungsi ini untuk dibuka.

    Parameter:
        ciphertext : bytes dari DB (kolom password_entries.password_enc)
        iv         : bytes dari DB (kolom password_entries.iv)
        auth_tag   : bytes dari DB (kolom password_entries.auth_tag)
        kunci_aes  : bytes kunci AES aktif dari sesi login

    Mengembalikan:
        str — password asli yang bisa dibaca (contoh: "p@$$w0rd!")

    Melempar Exception jika:
        - kunci salah
        - data dirusak (auth_tag tidak cocok)
    """
    mesin_aes = AESGCM(kunci_aes)

    # Gabungkan kembali ciphertext + auth_tag sebelum dekripsi
    gabungan = ciphertext + auth_tag

    hasil = mesin_aes.decrypt(iv, gabungan, None)
    return hasil.decode('utf-8')


# ─────────────────────────────────────────────────────────────
#  BAGIAN 5: FITUR FORGOT PASSWORD — TOKEN RECOVERY
#
#  Alur:
#    1. User klik "Lupa Master Key" di UI (William)
#    2. generate_token_recovery() buat token acak 32 byte
#    3. Hash token disimpan ke DB (Habil):
#         → user.recovery_token_hash
#         → user.recovery_expires_at (berlaku 1 jam)
#    4. Token asli ditampilkan SEKALI ke user (screenshot/catat)
#    5. User masukkan token → verifikasi_token_recovery()
#    6. Jika cocok & belum kadaluarsa → izinkan ganti Master Key
# ─────────────────────────────────────────────────────────────

def generate_token_recovery() -> tuple[str, bytes, datetime]:
    """
    Buat token recovery untuk fitur Lupa Master Key.

    Dipanggil William saat user klik "Lupa Master Key".
    Hasilnya:
      - token_teks   : ditampilkan ke user (SEKALI SAJA, catat/screenshot!)
      - hash_token   : disimpan Habil ke DB (kolom user.recovery_token_hash)
      - waktu_expired: disimpan Habil ke DB (kolom user.recovery_expires_at)

    Mengembalikan tuple (3 nilai):
        (token_teks_str, hash_token_bytes, waktu_kadaluarsa_datetime)
    """
    # Buat token acak 32 byte (256 bit) — sangat sulit ditebak
    token_mentah = secrets.token_bytes(32)

    # Token yang ditampilkan ke user dalam format hex (mudah dicopy)
    token_teks = token_mentah.hex()

    # Hash token untuk disimpan ke DB (jangan simpan token aslinya!)
    hash_token = hashlib.sha256(token_mentah).digest()

    # Token berlaku 1 jam dari sekarang
    waktu_expired = datetime.now() + timedelta(hours=1)

    return token_teks, hash_token, waktu_expired


def verifikasi_token_recovery(
    token_input   : str,
    hash_tersimpan: bytes,
    waktu_expired : datetime
) -> bool:
    """
    Cek apakah token recovery yang dimasukkan user valid.

    Dipanggil William saat user submit token recovery.

    Parameter:
        token_input    : string hex yang diketik/paste user
        hash_tersimpan : bytes dari DB (kolom user.recovery_token_hash)
        waktu_expired  : datetime dari DB (kolom user.recovery_expires_at)

    Mengembalikan:
        True  → token benar & belum kadaluarsa → izinkan ganti Master Key
        False → token salah atau sudah kadaluarsa
    """
    # Cek apakah token sudah kadaluarsa
    if datetime.now() > waktu_expired:
        return False  # sudah lebih dari 1 jam

    # Ubah input hex kembali ke bytes, hash, lalu bandingkan
    try:
        token_bytes_input = bytes.fromhex(token_input)
    except ValueError:
        return False  # bukan format hex yang valid

    hash_input = hashlib.sha256(token_bytes_input).digest()
    return hmac.compare_digest(hash_input, hash_tersimpan)


def ganti_master_key(
    master_key_baru: str
) -> tuple[bytes, bytes]:
    """
    Buat salt baru dan hash baru dari Master Key pengganti.

    Dipanggil William setelah verifikasi_token_recovery() = True.
    Hasilnya dikirim ke Habil untuk update tabel user.

    Parameter:
        master_key_baru : string Master Key baru yang diinput user

    Mengembalikan tuple (2 nilai):
        (salt_baru_bytes, hash_baru_bytes)
        → Habil update ke: user.salt, user.master_hash
    """
    salt_baru = generate_salt()
    hash_baru = hash_master_key(master_key_baru, salt_baru)
    return salt_baru, hash_baru


# ─────────────────────────────────────────────────────────────
#  BAGIAN 6: TEST MANDIRI
#  Jalankan: python crypto.py
#  Pastikan semua test menampilkan ✓ sebelum kirim ke William!
# ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 55)
    print("  TEST MODUL CRYPTO.PY — SecureVault Kelompok 2")
    print("=" * 55)

    # ── Test 1: Salt ──────────────────────────────────────────
    print("\n[ Test 1: generate_salt() ]")
    salt = generate_salt()
    print(f"  Salt (hex) : {salt.hex()}")
    print(f"  Panjang    : {len(salt)} byte")
    assert len(salt) == 32, "GAGAL: panjang salt harus 32 byte"
    print("  Hasil      : ✓ LULUS")

    # ── Test 2: Hash Master Key ───────────────────────────────
    print("\n[ Test 2: hash_master_key() ]")
    MASTER_KEY_TEST = "MasterKeySeka2024!"
    kunci_aes = hash_master_key(MASTER_KEY_TEST, salt)
    print(f"  Kunci AES  : {kunci_aes.hex()[:32]}...")
    print(f"  Panjang    : {len(kunci_aes)} byte (harus 32)")
    assert len(kunci_aes) == 32, "GAGAL: kunci harus 32 byte"
    print("  Hasil      : ✓ LULUS")

    # ── Test 3: Verifikasi Master Key ─────────────────────────
    print("\n[ Test 3: verifikasi_master_key() ]")
    benar = verifikasi_master_key(MASTER_KEY_TEST, kunci_aes, salt)
    salah = verifikasi_master_key("PasswordSalah123", kunci_aes, salt)
    print(f"  Input benar : {benar}  (harus True)")
    print(f"  Input salah : {salah} (harus False)")
    assert benar == True and salah == False, "GAGAL verifikasi"
    print("  Hasil       : ✓ LULUS")

    # ── Test 4: Enkripsi & Dekripsi ───────────────────────────
    print("\n[ Test 4: enkripsi_password() & dekripsi_password() ]")
    PASSWORD_ASLI = "p@$$w0rdInstagram2024!"
    ciphertext, iv, auth_tag = enkripsi_password(PASSWORD_ASLI, kunci_aes)
    print(f"  Ciphertext  : {ciphertext.hex()[:24]}... ({len(ciphertext)} byte)")
    print(f"  IV          : {iv.hex()} ({len(iv)} byte)")
    print(f"  Auth Tag    : {auth_tag.hex()} ({len(auth_tag)} byte)")
    hasil_dekripsi = dekripsi_password(ciphertext, iv, auth_tag, kunci_aes)
    print(f"  Dekripsi    : {hasil_dekripsi}")
    assert hasil_dekripsi == PASSWORD_ASLI, "GAGAL: hasil dekripsi tidak cocok"
    print("  Hasil       : ✓ LULUS")

    # ── Test 5: Enkripsi dengan kunci salah (harus error) ─────
    print("\n[ Test 5: dekripsi dengan kunci salah ]")
    kunci_palsu = os.urandom(32)
    try:
        dekripsi_password(ciphertext, iv, auth_tag, kunci_palsu)
        print("  Hasil : ✗ GAGAL (seharusnya melempar exception!)")
    except Exception as e:
        print(f"  Exception tertangkap: {type(e).__name__}")
        print("  Hasil : ✓ LULUS (AES-GCM berhasil deteksi kunci salah)")

    # ── Test 6: Token Recovery ────────────────────────────────
    print("\n[ Test 6: generate_token_recovery() & verifikasi ]")
    token_teks, hash_token, waktu_exp = generate_token_recovery()
    print(f"  Token (hex) : {token_teks[:32]}...")
    print(f"  Hash token  : {hash_token.hex()[:32]}...")
    print(f"  Kadaluarsa  : {waktu_exp.strftime('%H:%M:%S')}")
    valid = verifikasi_token_recovery(token_teks, hash_token, waktu_exp)
    tidak_valid = verifikasi_token_recovery("tokenpalsu123abc", hash_token, waktu_exp)
    print(f"  Token benar : {valid}  (harus True)")
    print(f"  Token salah : {tidak_valid} (harus False)")
    assert valid == True and tidak_valid == False
    print("  Hasil       : ✓ LULUS")

    # ── Test 7: Ganti Master Key ──────────────────────────────
    print("\n[ Test 7: ganti_master_key() ]")
    salt_baru, hash_baru = ganti_master_key("MasterKeyBaru2024!")
    print(f"  Salt baru   : {salt_baru.hex()[:32]}...")
    print(f"  Hash baru   : {hash_baru.hex()[:32]}...")
    benar_baru = verifikasi_master_key("MasterKeyBaru2024!", hash_baru, salt_baru)
    print(f"  Verifikasi  : {benar_baru} (harus True)")
    assert benar_baru == True
    print("  Hasil       : ✓ LULUS")

    print("\n" + "=" * 55)
    print("  SEMUA TEST LULUS — crypto.py siap dikirim!")
    print("=" * 55)
