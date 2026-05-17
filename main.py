import tkinter as tk
from tkinter import messagebox, ttk
import random
import string
from datetime import datetime

from crypto import (
    generate_salt,
    hash_master_key,
    verifikasi_master_key,
    enkripsi_password,
    dekripsi_password,
    generate_token_recovery,
    verifikasi_token_recovery,
    ganti_master_key
)

import database

class SecureVaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureVault")
        self.root.geometry("750x650")
        
        style = ttk.Style()
        if 'clam' in style.theme_names():
            style.theme_use('clam')
            
        bg_color = "#F0F4F8"
        self.root.configure(bg=bg_color)
        
        style.configure('TFrame', background=bg_color)
        style.configure('TLabel', background=bg_color, font=('Inter', 11))
        style.configure('Header.TLabel', background=bg_color, font=('Inter', 22, 'bold'), foreground='#2C3E50')
        style.configure('SubHeader.TLabel', background=bg_color, font=('Inter', 14, 'bold'), foreground='#34495E')
        style.configure('TButton', font=('Inter', 10, 'bold'), padding=6)
        style.configure('Primary.TButton', font=('Inter', 10, 'bold'), padding=6, background='#3498DB', foreground='white')
        style.map('Primary.TButton', background=[('active', '#2980B9')])
        style.configure('Danger.TButton', font=('Inter', 10, 'bold'), padding=6, background='#E74C3C', foreground='white')
        style.map('Danger.TButton', background=[('active', '#C0392B')])
        
        self.current_user = None
        self.kunci_aes_aktif = None
        
        self.show_login()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_register(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding=40)
        frame.pack(expand=True)
        
        ttk.Label(frame, text="Daftar Akun Baru", style='Header.TLabel').pack(pady=(0, 20))
        
        ttk.Label(frame, text="Username").pack(anchor="w")
        entry_user = ttk.Entry(frame, width=35, font=('Inter', 11))
        entry_user.pack(pady=(5, 15), ipady=5)
        
        ttk.Label(frame, text="Master Key").pack(anchor="w")
        entry_pass = ttk.Entry(frame, width=35, show="*", font=('Inter', 11))
        entry_pass.pack(pady=(5, 15), ipady=5)
        
        ttk.Label(frame, text="Konfirmasi Master Key").pack(anchor="w")
        entry_pass2 = ttk.Entry(frame, width=35, show="*", font=('Inter', 11))
        entry_pass2.pack(pady=(5, 25), ipady=5)
        
        def do_register():
            user = entry_user.get()
            pw1 = entry_pass.get()
            pw2 = entry_pass2.get()
            
            if not user or not pw1:
                messagebox.showerror("Error", "Semua field harus diisi!")
                return
            if pw1 != pw2:
                messagebox.showerror("Error", "Konfirmasi Master Key tidak cocok!")
                return
            
            salt = generate_salt()
            master_hash = hash_master_key(pw1, salt)
            
            if database.create_user(user, salt, master_hash):
                messagebox.showinfo("Sukses", "Akun berhasil didaftarkan. Silakan login.")
                self.show_login()
            else:
                messagebox.showerror("Error", "Gagal mendaftar (mungkin username sudah ada)")

        ttk.Button(frame, text="DAFTAR SEKARANG", style='Primary.TButton', command=do_register, width=25).pack(pady=5)
        ttk.Button(frame, text="Kembali ke Login", command=self.show_login, width=25).pack(pady=5)

    def show_login(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding=40)
        frame.pack(expand=True)
        
        ttk.Label(frame, text="SecureVault", style='Header.TLabel').pack(pady=(0, 5))
        ttk.Label(frame, text="Silakan masuk untuk mengakses brankas Anda", font=('Inter', 10), foreground="#7F8C8D").pack(pady=(0, 25))
        
        ttk.Label(frame, text="Username").pack(anchor="w")
        entry_user = ttk.Entry(frame, width=35, font=('Inter', 11))
        entry_user.pack(pady=(5, 15), ipady=5)
        
        ttk.Label(frame, text="Master Key").pack(anchor="w")
        entry_pass = ttk.Entry(frame, width=35, show="*", font=('Inter', 11))
        entry_pass.pack(pady=(5, 25), ipady=5)
        
        def do_login():
            username = entry_user.get()
            input_key = entry_pass.get()
            
            user_data = database.get_user_by_username(username)
            if not user_data:
                messagebox.showerror("Error", "Username tidak ditemukan. Silakan daftar terlebih dahulu.")
                self.show_register()
                return
            
            if user_data['locked_until'] and user_data['locked_until'] > datetime.now():
                messagebox.showerror("Error", f"Akun dikunci hingga {user_data['locked_until']}")
                return
                
            salt = user_data['salt']
            hash_tersimpan = user_data['master_hash']
            
            if verifikasi_master_key(input_key, hash_tersimpan, salt):
                # Login sukses
                database.update_login_attempts(user_data['id'], 0, None)
                database.add_audit_log(user_data['id'], "LOGIN_OK")
                
                self.current_user = user_data
                self.kunci_aes_aktif = hash_master_key(input_key, salt)
                self.show_vault()
            else:
                # Login gagal
                attempts = user_data['failed_attempts'] + 1
                if attempts >= 3:
                    import datetime as dt
                    locked_until = dt.datetime.now() + dt.timedelta(minutes=5)
                    database.update_login_attempts(user_data['id'], attempts, locked_until)
                    database.add_audit_log(user_data['id'], "ACCOUNT_LOCKED")
                    messagebox.showerror("Error", "Terlalu banyak percobaan gagal. Akun dikunci 5 menit.")
                else:
                    database.update_login_attempts(user_data['id'], attempts)
                    database.add_audit_log(user_data['id'], "LOGIN_FAIL")
                    messagebox.showerror("Error", f"Master Key salah! Percobaan {attempts}/3")

        ttk.Button(frame, text="LOGIN", style='Primary.TButton', command=do_login, width=25).pack(pady=5)
        ttk.Button(frame, text="Belum punya akun? Daftar", command=self.show_register, width=25).pack(pady=5)
        ttk.Button(frame, text="Lupa Master Key?", command=self.show_forgot_password, width=25).pack(pady=5)

    def show_forgot_password(self):
        window_reset = tk.Toplevel(self.root)
        window_reset.title("Lupa Master Key")
        window_reset.geometry("450x450")
        window_reset.configure(bg="#F0F4F8")
        
        frame = ttk.Frame(window_reset, padding=20)
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="Lupa Master Key", style='SubHeader.TLabel').pack(pady=(0, 15))
        
        ttk.Label(frame, text="Username").pack(anchor="w")
        entry_user = ttk.Entry(frame, width=40, font=('Inter', 11))
        entry_user.pack(pady=(5, 10), ipady=4)
        
        token_var = tk.StringVar()
        
        def request_token():
            username = entry_user.get()
            user_data = database.get_user_by_username(username)
            if not user_data:
                messagebox.showerror("Error", "Username tidak ditemukan", parent=window_reset)
                return
            
            token_teks, hash_token, waktu_exp = generate_token_recovery()
            database.save_recovery_token(user_data['id'], hash_token, waktu_exp)
            
            token_var.set(token_teks)
            messagebox.showinfo("INFO PENTING", f"Simpan token ini baik-baik. Hanya tampil sekali!\n\n{token_teks}", parent=window_reset)
        
        ttk.Button(frame, text="Minta Token Recovery", command=request_token).pack(pady=(0, 20))
        
        ttk.Label(frame, text="Masukkan Token Recovery").pack(anchor="w")
        entry_token = ttk.Entry(frame, width=40, font=('Inter', 11))
        entry_token.pack(pady=(5, 10), ipady=4)
        
        ttk.Label(frame, text="Master Key Baru").pack(anchor="w")
        entry_master_baru = ttk.Entry(frame, width=40, show="*", font=('Inter', 11))
        entry_master_baru.pack(pady=(5, 15), ipady=4)
        
        def do_reset():
            username = entry_user.get()
            token_input = entry_token.get()
            master_baru = entry_master_baru.get()
            
            user_data = database.get_user_by_username(username)
            if not user_data:
                return
                
            if not user_data['recovery_token_hash']:
                messagebox.showerror("Error", "Belum ada token di-generate", parent=window_reset)
                return
                
            valid = verifikasi_token_recovery(token_input, user_data['recovery_token_hash'], user_data['recovery_expires_at'])
            
            if valid:
                salt_baru, hash_baru = ganti_master_key(master_baru)
                database.update_master_key(user_data['id'], salt_baru, hash_baru)
                # Catatan: audit log reset sudah ditangani di database.update_master_key
                
                messagebox.showinfo("Sukses", "Master Key berhasil direset. Catatan: password lama mungkin tidak bisa diakses tanpa kunci asli.", parent=window_reset)
                window_reset.destroy()
            else:
                messagebox.showerror("Error", "Token salah atau sudah kadaluarsa", parent=window_reset)
                
        ttk.Button(frame, text="Reset Master Key", style='Primary.TButton', command=do_reset).pack(pady=10)

    def show_vault(self):
        self.clear_window()
        
        frame_main = ttk.Frame(self.root, padding=20)
        frame_main.pack(fill="both", expand=True)
        
        header = ttk.Frame(frame_main)
        header.pack(fill="x", pady=(0, 20))
        
        ttk.Label(header, text=f"Brankas: {self.current_user['username']}", style='Header.TLabel').pack(side=tk.LEFT)
        
        ttk.Button(header, text="Logout", command=self.show_login).pack(side=tk.RIGHT)
        ttk.Button(header, text="Ganti Master Key", command=self.show_change_master_key).pack(side=tk.RIGHT, padx=10)
        
        # Frame untuk tombol-tombol (diposisikan di bawah agar tidak tertutup tabel)
        frame_btn = ttk.Frame(frame_main)
        frame_btn.pack(side=tk.BOTTOM, fill="x", pady=(10, 0))
        
        ttk.Button(frame_btn, text="+ Tambah Password", style='Primary.TButton', command=self.show_add_password).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(frame_btn, text="Lihat Password", command=self.lihat_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(frame_btn, text="Copy Password", command=self.copy_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(frame_btn, text="Hapus", style='Danger.TButton', command=self.hapus_password).pack(side=tk.LEFT, padx=5)

        # Frame pembungkus khusus untuk tabel
        frame_tabel = ttk.Frame(frame_main)
        frame_tabel.pack(side=tk.TOP, fill="both", expand=True)

        # Tabel Vault
        columns = ("ID", "Website", "Username", "Password")
        
        # Styling Treeview
        style = ttk.Style()
        style.configure("Treeview", font=('Inter', 11), rowheight=30)
        style.configure("Treeview.Heading", font=('Inter', 11, 'bold'))
        
        self.tree = ttk.Treeview(frame_tabel, columns=columns, show="headings", height=10)
        self.tree.heading("ID", text="ID")
        self.tree.column("ID", width=0, stretch=tk.NO) # Hide ID
        self.tree.heading("Website", text="Website / Aplikasi")
        self.tree.column("Website", width=200)
        self.tree.heading("Username", text="Username / Email")
        self.tree.column("Username", width=200)
        self.tree.heading("Password", text="Password")
        self.tree.column("Password", width=150)
        
        # Scrollbar untuk tabel
        scrollbar = ttk.Scrollbar(frame_tabel, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(side=tk.LEFT, fill="both", expand=True)
        
        self.load_vault_data()
        
    def load_vault_data(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        passwords = database.get_passwords(self.current_user['id'])
        for p in passwords:
            self.tree.insert("", "end", values=(p['id'], p['site_name'], p['username_hint'], "••••••••"))
            
    def show_add_password(self):
        win_add = tk.Toplevel(self.root)
        win_add.title("Tambah Password")
        win_add.geometry("400x350")
        win_add.configure(bg="#F0F4F8")
        
        frame = ttk.Frame(win_add, padding=20)
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="Tambah Akun Baru", style='SubHeader.TLabel').pack(pady=(0, 15))
        
        ttk.Label(frame, text="Website / Aplikasi").pack(anchor="w")
        entry_web = ttk.Entry(frame, width=35, font=('Inter', 11))
        entry_web.pack(pady=(5, 10), ipady=4)
        
        ttk.Label(frame, text="Username / Email").pack(anchor="w")
        entry_usr = ttk.Entry(frame, width=35, font=('Inter', 11))
        entry_usr.pack(pady=(5, 10), ipady=4)
        
        ttk.Label(frame, text="Password").pack(anchor="w")
        entry_pwd = ttk.Entry(frame, width=35, show="*", font=('Inter', 11))
        entry_pwd.pack(pady=(5, 15), ipady=4)
        
        def simpan():
            w = entry_web.get()
            u = entry_usr.get()
            p = entry_pwd.get()
            
            if not w or not u or not p:
                messagebox.showerror("Error", "Semua field harus diisi", parent=win_add)
                return
                
            c, iv, auth = enkripsi_password(p, self.kunci_aes_aktif)
            
            if database.add_password_entry(self.current_user['id'], w, u, c, iv, auth):
                database.add_audit_log(self.current_user['id'], "ENTRY_CREATE")
                messagebox.showinfo("Sukses", "Password berhasil disimpan", parent=win_add)
                self.load_vault_data()
                win_add.destroy()
            else:
                messagebox.showerror("Error", "Gagal menyimpan ke database", parent=win_add)
                
        ttk.Button(frame, text="Simpan Password", style='Primary.TButton', command=simpan).pack(pady=10)

    def get_selected_password_data(self):
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning("Warning", "Pilih data di tabel dulu")
            return None
            
        item_values = self.tree.item(selected, "values")
        entry_id = int(item_values[0])
        
        passwords = database.get_passwords(self.current_user['id'])
        for p in passwords:
            if p['id'] == entry_id:
                return p
        return None

    def lihat_password(self):
        p = self.get_selected_password_data()
        if not p: return
        
        try:
            asli = dekripsi_password(p['password_enc'], p['iv'], p['auth_tag'], self.kunci_aes_aktif)
            messagebox.showinfo("Lihat Password", f"Website: {p['site_name']}\nUsername: {p['username_hint']}\n\nPassword: {asli}")
            database.add_audit_log(self.current_user['id'], "ENTRY_READ")
        except Exception:
            messagebox.showerror("Error", "Gagal mendekripsi. Apakah Master Key sudah berubah tanpa re-enkripsi?")

    def copy_password(self):
        p = self.get_selected_password_data()
        if not p: return
        
        try:
            asli = dekripsi_password(p['password_enc'], p['iv'], p['auth_tag'], self.kunci_aes_aktif)
            self.root.clipboard_clear()
            self.root.clipboard_append(asli)
            messagebox.showinfo("Sukses", "Password berhasil disalin ke clipboard")
            database.add_audit_log(self.current_user['id'], "ENTRY_READ")
        except Exception:
            messagebox.showerror("Error", "Gagal mendekripsi password")

    def hapus_password(self):
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning("Warning", "Pilih data di tabel dulu")
            return
            
        item_values = self.tree.item(selected, "values")
        entry_id = int(item_values[0])
        website = item_values[1]
        
        if messagebox.askyesno("Konfirmasi", f"Yakin ingin menghapus password untuk {website}?"):
            if database.delete_password(entry_id):
                database.add_audit_log(self.current_user['id'], "ENTRY_DELETE")
                self.load_vault_data()
                messagebox.showinfo("Sukses", "Data dihapus")

    def show_change_master_key(self):
        win_change = tk.Toplevel(self.root)
        win_change.title("Ganti Master Key")
        win_change.geometry("400x300")
        win_change.configure(bg="#F0F4F8")
        
        frame = ttk.Frame(win_change, padding=20)
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="Ganti Master Key", style='SubHeader.TLabel').pack(pady=(0, 10))
        ttk.Label(frame, text="Proses re-enkripsi data akan dilakukan otomatis.", foreground="#7F8C8D").pack(pady=(0, 15))
        
        ttk.Label(frame, text="Master Key Baru").pack(anchor="w")
        entry_new = ttk.Entry(frame, width=35, show="*", font=('Inter', 11))
        entry_new.pack(pady=(5, 20), ipady=4)
        
        def simpan_ganti():
            mb = entry_new.get()
            if not mb: return
            
            salt_baru, hash_baru = ganti_master_key(mb)
            kunci_aes_baru = hash_master_key(mb, salt_baru)
            passwords = database.get_passwords(self.current_user['id'])
            
            try:
                for p in passwords:
                    asli = dekripsi_password(p['password_enc'], p['iv'], p['auth_tag'], self.kunci_aes_aktif)
                    c_new, iv_new, auth_new = enkripsi_password(asli, kunci_aes_baru)
                    database.update_password_encryption(p['id'], c_new, iv_new, auth_new)
                    database.add_audit_log(self.current_user['id'], "ENTRY_UPDATE")
            except Exception as e:
                messagebox.showerror("Error", f"Gagal re-enkripsi: {e}", parent=win_change)
                return
                
            database.update_master_key(self.current_user['id'], salt_baru, hash_baru)
            self.kunci_aes_aktif = kunci_aes_baru
            
            messagebox.showinfo("Sukses", "Master Key berhasil diganti dan semua password telah dire-enkripsi!", parent=win_change)
            win_change.destroy()
            
        ttk.Button(frame, text="Ganti & Re-enkripsi", style='Primary.TButton', command=simpan_ganti).pack(pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureVaultApp(root)
    root.mainloop()
