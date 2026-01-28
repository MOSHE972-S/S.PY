import sys
import os
import threading
import struct
import gc
import base64
import json
import datetime
import time
import zlib
import hmac
import hashlib
from concurrent.futures import ThreadPoolExecutor

# --- מנגנון הגנה מפני קריסות ---
try:
    import customtkinter as ctk
    from tkinter import filedialog
    # הערה: אנו לא משתמשים ב-messagebox רגיל כדי לשלוט בשפה
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as e:
    import tkinter as tk
    from tkinter import messagebox
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("שגיאה", f"חסרות ספריות: {e}\nנא להריץ בטרמינל:\npip install customtkinter cryptography")
    sys.exit(1)

# =============================================================================
# הגדרות מערכת
# =============================================================================
APP_NAME = "כספת ברזל (IronClad)"
VERSION = "v17.5 Hebrew Edition"
CHUNK_SIZE = 4 * 1024 * 1024  # 4MB
MAGIC_HEADER = b'IRON_V17'

# ערכת נושא (Dark Mode)
THEME = {
    "bg": "#0B0E14",          
    "panel": "#151922",       
    "primary": "#6366F1",     
    "danger": "#F43F5E",      
    "success": "#10B981",     
    "text": "#E2E8F0",        
    "text_dim": "#94A3B8",    
    "border": "#1E293B"       
}

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

# =============================================================================
# רכיבי GUI מותאמים אישית (לעברית מלאה)
# =============================================================================

class HebrewDialog(ctk.CTkToplevel):
    """ חלונית קלט/אישור מעוצבת בעברית מלאה """
    def __init__(self, parent, title, message, mode="input", is_password=False):
        super().__init__(parent)
        self.title(title)
        self.geometry("400x220")
        self.resizable(False, False)
        self.configure(fg_color=THEME["bg"])
        
        # מרכוז החלון
        self.transient(parent)
        self.grab_set()
        
        # כותרת ההודעה (מיושר לימין)
        self.lbl = ctk.CTkLabel(self, text=message, font=("Segoe UI", 14), text_color=THEME["text"], wraplength=350, justify="right")
        self.lbl.pack(pady=20, padx=20, anchor="e")
        
        self.result = None
        
        # מצב קלט (Input)
        if mode == "input":
            self.entry = ctk.CTkEntry(self, width=300, justify="right", font=("Segoe UI", 13))
            if is_password:
                self.entry.configure(show="*")
            self.entry.pack(pady=10)
            self.entry.focus()
            
            btn_frame = ctk.CTkFrame(self, fg_color="transparent")
            btn_frame.pack(pady=20)
            
            ctk.CTkButton(btn_frame, text="אישור", width=100, command=self.on_ok, fg_color=THEME["success"]).pack(side="right", padx=10)
            ctk.CTkButton(btn_frame, text="ביטול", width=100, command=self.on_cancel, fg_color=THEME["danger"]).pack(side="left", padx=10)
            
            self.bind('<Return>', lambda e: self.on_ok())
            
        # מצב אישור (Yes/No)
        elif mode == "confirm":
            btn_frame = ctk.CTkFrame(self, fg_color="transparent")
            btn_frame.pack(pady=30)
            
            ctk.CTkButton(btn_frame, text="כן, אני בטוח", width=120, command=self.on_yes, fg_color=THEME["danger"]).pack(side="right", padx=10)
            ctk.CTkButton(btn_frame, text="לא, בטל", width=120, command=self.on_no, fg_color=THEME["primary"]).pack(side="left", padx=10)
            
        elif mode == "info":
             ctk.CTkButton(self, text="סגור", width=100, command=self.destroy, fg_color=THEME["primary"]).pack(pady=20)

        self.wait_window()

    def on_ok(self):
        self.result = self.entry.get()
        self.destroy()
    def on_cancel(self):
        self.result = None
        self.destroy()
    def on_yes(self):
        self.result = True
        self.destroy()
    def on_no(self):
        self.result = False
        self.destroy()

# =============================================================================
# מנוע קריפטוגרפי (Logic)
# =============================================================================
class SecureKey:
    def __init__(self, key_bytes):
        self._key = bytearray(key_bytes)
    def get(self):
        if not self._key: return None
        return bytes(self._key)
    def wipe(self):
        if self._key:
            for i in range(len(self._key)): self._key[i] = 0
            self._key = None

class CryptoEngine:
    def __init__(self):
        self.secure_key_obj = None
        self.cancel_flag = threading.Event()

    def is_locked(self): return self.secure_key_obj is None
    def get_key(self): return self.secure_key_obj.get() if self.secure_key_obj else None

    def derive_kek(self, password: str, salt: bytes) -> bytes:
        kdf = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
        return base64.urlsafe_b64encode(kdf)

    def create_key_file(self, path, password):
        master_key = AESGCM.generate_key(bit_length=256)
        salt = os.urandom(16)
        kek = self.derive_kek(password, salt)
        fernet = Fernet(kek)
        encrypted_key_blob = fernet.encrypt(master_key)
        h = hmac.new(kek, salt + encrypted_key_blob, hashlib.sha256)
        signature = h.digest()
        with open(path, "wb") as f:
            f.write(salt + signature + encrypted_key_blob)
        self.secure_key_obj = SecureKey(master_key)
        del master_key

    def load_key_file(self, path, password):
        time.sleep(0.5) 
        with open(path, "rb") as f: data = f.read()
        if len(data) < 48: raise ValueError("קובץ מפתח לא תקין")
        salt = data[:16]
        signature = data[16:48]
        enc_blob = data[48:]
        kek = self.derive_kek(password, salt)
        h = hmac.new(kek, salt + enc_blob, hashlib.sha256)
        if not hmac.compare_digest(h.digest(), signature):
            time.sleep(1.0)
            raise ValueError("אימות נכשל: סיסמה שגויה או קובץ פגום")
        try:
            master_key = Fernet(kek).decrypt(enc_blob)
            self.secure_key_obj = SecureKey(master_key)
            del master_key
        except:
            time.sleep(1.0)
            raise ValueError("סיסמה שגויה")

    def unload(self):
        if self.secure_key_obj: self.secure_key_obj.wipe()
        self.secure_key_obj = None
        gc.collect()

    def secure_shred(self, path):
        if not os.path.exists(path): return
        try:
            length = os.path.getsize(path)
            with open(path, "r+b") as f:
                f.write(os.urandom(length))
                f.flush(); os.fsync(f.fileno())
            os.remove(path)
        except: pass

# =============================================================================
# אפליקציה ראשית (GUI)
# =============================================================================
class HebrewCyberApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} | {VERSION}")
        self.geometry("1100x800")
        self.configure(fg_color=THEME["bg"])
        
        self.engine = CryptoEngine()
        self.executor = ThreadPoolExecutor(max_workers=1)
        
        # RTL Grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0)
        self.grid_rowconfigure(0, weight=1)

        self.setup_sidebar()
        self.setup_main_area()
        self.setup_status_bar()
        
        self._last_ui_update = 0
        self.log("מערכת הליבה v17.5 נטענה.", "info")

    def show_error(self, title, message):
        HebrewDialog(self, title, message, mode="info")

    def show_info(self, title, message):
        HebrewDialog(self, title, message, mode="info")

    def ask_input(self, title, message, is_password=False):
        dialog = HebrewDialog(self, title, message, mode="input", is_password=is_password)
        return dialog.result

    def ask_confirm(self, title, message):
        dialog = HebrewDialog(self, title, message, mode="confirm")
        return dialog.result

    def setup_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color=THEME["panel"])
        self.sidebar.grid(row=0, column=1, sticky="nsew")
        self.sidebar.grid_propagate(False)

        ctk.CTkLabel(self.sidebar, text="🔒", font=("Segoe UI", 48)).pack(pady=(40, 10))
        ctk.CTkLabel(self.sidebar, text="כספת ברזל", font=("Segoe UI", 26, "bold"), text_color=THEME["text"]).pack()
        ctk.CTkLabel(self.sidebar, text="אבטחה ישראלית", font=("Segoe UI", 12, "bold"), text_color=THEME["primary"]).pack()
        
        self.status_container = ctk.CTkFrame(self.sidebar, fg_color=THEME["bg"], border_width=1, border_color=THEME["border"])
        self.status_container.pack(fill="x", padx=20, pady=30)
        
        self.lbl_lock_status = ctk.CTkLabel(self.status_container, text="מערכת נעולה", font=("Segoe UI", 14, "bold"), text_color=THEME["danger"])
        self.lbl_lock_status.pack(pady=10)

        self.create_side_btn("יצירת מפתח חדש", self.cmd_generate_key, "✨")
        self.create_side_btn("טעינת מפתח קיים", self.cmd_load_key, "📂")
        self.btn_unload = self.create_side_btn("נעילת כספת", self.cmd_unload_key, "🔒", fg=THEME["danger"])
        self.btn_unload.configure(state="disabled")

    def setup_main_area(self):
        self.main_view = ctk.CTkFrame(self, fg_color="transparent")
        self.main_view.grid(row=0, column=0, sticky="nsew", padx=30, pady=30)

        self.tabview = ctk.CTkTabview(self.main_view, width=800, height=450, fg_color=THEME["panel"])
        self.tabview.pack(fill="x")
        self.tab_enc = self.tabview.add("   הצפנה   ")
        self.tab_dec = self.tabview.add("   פענוח   ")

        self.setup_encryption_ui()
        self.setup_decryption_ui()

        ctk.CTkLabel(self.main_view, text="יומן אירועים", font=("Segoe UI", 12, "bold"), text_color=THEME["text_dim"]).pack(anchor="e", pady=(20, 5))
        self.log_box = ctk.CTkTextbox(self.main_view, height=150, font=("Consolas", 12), fg_color=THEME["bg"])
        self.log_box.pack(fill="both", expand=True)
        self.log_box.tag_config("rtl", justify="right")

    def setup_encryption_ui(self):
        f = ctk.CTkFrame(self.tab_enc, fg_color="transparent")
        f.pack(expand=True, fill="both", padx=40, pady=30)
        
        self.chk_compress = ctk.CTkCheckBox(f, text="דחיסת נתונים (מומלץ לקבצים גדולים)", font=("Segoe UI", 12), text_color=THEME["text"], onvalue=1, offvalue=0)
        self.chk_compress.pack(anchor="ne", pady=5)
        self.chk_compress.select() 
        
        self.chk_shred = ctk.CTkCheckBox(f, text="גריסת קובץ המקור בסיום (ללא יכולת שחזור)", font=("Segoe UI", 12), text_color=THEME["text_dim"], hover_color=THEME["danger"], fg_color=THEME["danger"])
        self.chk_shred.pack(anchor="ne", pady=5)

        self.btn_encrypt = ctk.CTkButton(f, text="בחר קובץ להצפנה", font=("Segoe UI", 16, "bold"), height=60, command=self.run_encryption)
        self.btn_encrypt.pack(fill="x", pady=40)
        
        ctk.CTkLabel(f, text="AES-256-GCM • Scrypt • הצפנת מטא-דאטה", font=("Segoe UI", 10), text_color=THEME["text_dim"]).pack()

    def setup_decryption_ui(self):
        f = ctk.CTkFrame(self.tab_dec, fg_color="transparent")
        f.pack(expand=True, fill="both", padx=40, pady=40)
        self.btn_decrypt = ctk.CTkButton(f, text="בחר קובץ לשחזור", font=("Segoe UI", 16, "bold"), height=60, command=self.run_decryption, fg_color=THEME["primary"])
        self.btn_decrypt.pack(fill="x", pady=50)

    def setup_status_bar(self):
        self.status_bar = ctk.CTkFrame(self, height=35, fg_color=THEME["bg"])
        self.status_bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        
        self.btn_cancel = ctk.CTkButton(self.status_bar, text="עצור פעולה", fg_color=THEME["danger"], width=100, height=25, command=self.cancel_operation)
        self.btn_cancel.pack(side="right", padx=10)
        self.btn_cancel.pack_forget()

        self.progress_bar = ctk.CTkProgressBar(self.status_bar, height=10, progress_color=THEME["primary"])
        self.progress_bar.pack(side="left", fill="x", expand=True, padx=20)
        self.progress_bar.set(0)

    def create_side_btn(self, text, cmd, icon, fg="transparent"):
        btn = ctk.CTkButton(self.sidebar, text=f"{text}  {icon}  ", anchor="e", command=cmd, fg_color=fg, height=45, font=("Segoe UI", 13, "bold"))
        btn.pack(fill="x", padx=15, pady=8)
        return btn

    def log(self, msg, level="info"):
        t = datetime.datetime.now().strftime("%H:%M:%S")
        prefix = "שגיאה" if level == "error" else "הצלחה" if level == "success" else "מידע"
        self.log_box.insert("end", f"[{t}] {prefix}: {msg}\n", "rtl")
        self.log_box.see("end")

    def toggle_ui(self, locked):
        self.lbl_lock_status.configure(text="מערכת נעולה" if locked else "מערכת פעילה", text_color=THEME["danger"] if locked else THEME["success"])
        self.btn_unload.configure(state="disabled" if locked else "normal")

    def set_busy(self, busy):
        if busy:
            self.progress_bar.configure(mode="indeterminate")
            self.progress_bar.start()
            self.btn_cancel.pack(side="right", padx=10) 
            self.engine.cancel_flag.clear()
        else:
            self.progress_bar.stop()
            self.progress_bar.configure(mode="determinate")
            self.progress_bar.set(0)
            self.btn_cancel.pack_forget()

    def update_progress_throttled(self, curr, total):
        now = time.time()
        if now - self._last_ui_update < 0.1: return 
        self._last_ui_update = now
        self.after(0, lambda: self.progress_bar.set(curr / total))

    def cancel_operation(self):
        self.engine.cancel_flag.set()
        self.log("התקבלה בקשת עצירה...", "danger")

    # --- לוגיקה עסקית ---
    def cmd_generate_key(self):
        pwd = self.ask_input("יצירת מפתח", "בחר סיסמה חזקה להגנה על המפתח:", is_password=True)
        if not pwd: return
        path = filedialog.asksaveasfilename(defaultextension=".key", title="שמירת קובץ מפתח")
        if path: self.executor.submit(self._worker_gen_key, path, pwd)

    def _worker_gen_key(self, path, pwd):
        try:
            self.engine.create_key_file(path, pwd)
            self.after(0, lambda: self.log("מפתח חדש נוצר בהצלחה.", "success"))
            self.after(0, lambda: self.toggle_ui(False))
        except Exception as e: self.after(0, lambda: self.log(f"שגיאה ביצירה: {e}", "error"))

    def cmd_load_key(self):
        path = filedialog.askopenfilename(title="בחר קובץ מפתח")
        if not path: return
        pwd = self.ask_input("אימות", "הזן את סיסמת המפתח:", is_password=True)
        if not pwd: return
        self.executor.submit(self._worker_load_key, path, pwd)

    def _worker_load_key(self, path, pwd):
        try:
            self.engine.load_key_file(path, pwd)
            self.after(0, lambda: self.log("אימות עבר בהצלחה. המפתח נטען.", "success"))
            self.after(0, lambda: self.toggle_ui(False))
        except Exception as e: 
            self.after(0, lambda: self.show_error("גישה נדחתה", str(e)))
            self.after(0, lambda: self.log(f"כישלון באימות: {e}", "error"))

    def cmd_unload_key(self):
        self.engine.unload()
        self.toggle_ui(True)
        self.log("הכספת ננעלה.", "info")

    def run_encryption(self):
        if self.engine.is_locked(): return self.show_error("נעול", "יש לטעון מפתח תחילה (מתפריט הצד)")
        path = filedialog.askopenfilename(title="בחר קובץ להצפנה")
        if not path: return
        
        if self.chk_shred.get() == 1:
            if not self.ask_confirm("אזהרת גריסה", f"הקובץ המקורי:\n{os.path.basename(path)}\n\nיימחק לצמיתות בסיום התהליך.\nהאם אתה בטוח?"):
                return

        self.set_busy(True)
        self.executor.submit(self._worker_encrypt, path)

    def _worker_encrypt(self, path):
        try:
            f_size = os.path.getsize(path)
            dest = path + ".iron"
            
            meta_dict = {
                "orig": os.path.basename(path),
                "date": datetime.datetime.now().isoformat(),
                "comp": self.chk_compress.get()
            }
            meta_json = json.dumps(meta_dict).encode()
            
            aes = AESGCM(self.engine.get_key())
            meta_nonce = os.urandom(12)
            enc_meta = aes.encrypt(meta_nonce, meta_json, None)
            
            buf = bytearray(CHUNK_SIZE)
            processed = 0
            chunk_idx = 0
            
            with open(path, "rb", buffering=1024*1024) as inf, open(dest, "wb", buffering=1024*1024) as outf:
                outf.write(MAGIC_HEADER)
                outf.write(meta_nonce)
                outf.write(struct.pack('<I', len(enc_meta)))
                outf.write(enc_meta)
                
                while True:
                    if self.engine.cancel_flag.is_set(): raise RuntimeError("בוטל על ידי המשתמש")
                    bytes_read = inf.readinto(buf)
                    if not bytes_read: break
                    data_to_encrypt = memoryview(buf)[:bytes_read]
                    if self.chk_compress.get() == 1: data_to_encrypt = zlib.compress(data_to_encrypt)
                    nonce = os.urandom(12)
                    aad = struct.pack('<Q', chunk_idx)
                    ct = aes.encrypt(nonce, data_to_encrypt, associated_data=aad)
                    outf.write(nonce + struct.pack('<I', len(ct)) + ct)
                    processed += bytes_read
                    chunk_idx += 1
                    self.update_progress_throttled(processed, f_size)

            self.after(0, lambda: self.log(f"הוצפן בהצלחה: {dest}", "success"))
            self.after(0, lambda: self.show_info("הצלחה", "הקובץ הוצפן ואובטח."))
            if self.chk_shred.get()==1: self.engine.secure_shred(path)

        except Exception as e:
            self.after(0, lambda: self.log(f"נכשל: {e}", "error"))
            if os.path.exists(dest): os.remove(dest)
        finally: self.after(0, lambda: self.set_busy(False))

    def run_decryption(self):
        if self.engine.is_locked(): return self.show_error("נעול", "יש לטעון מפתח תחילה")
        path = filedialog.askopenfilename(filetypes=[("IronClad Files", "*.iron")], title="בחר קובץ לפענוח")
        if not path: return
        self.set_busy(True)
        self.executor.submit(self._worker_decrypt, path)

    def _worker_decrypt(self, path):
        try:
            f_size = os.path.getsize(path)
            aes = AESGCM(self.engine.get_key())
            processed = 0
            chunk_idx = 0
            
            with open(path, "rb", buffering=1024*1024) as inf:
                if inf.read(len(MAGIC_HEADER)) != MAGIC_HEADER: raise ValueError("קובץ לא תקין או גרסה ישנה")
                processed += len(MAGIC_HEADER)
                meta_nonce = inf.read(12)
                enc_meta_len = struct.unpack('<I', inf.read(4))[0]
                enc_meta = inf.read(enc_meta_len)
                try:
                    meta_json = aes.decrypt(meta_nonce, enc_meta, None)
                    meta = json.loads(meta_json)
                except: raise ValueError("כשל בפענוח מטא-דאטה (מפתח שגוי?)")
                processed += (16 + enc_meta_len)
                
                dest = os.path.join(os.path.dirname(path), "UNLOCKED_" + meta.get("orig", "file"))
                is_compressed = meta.get("comp", 0)
                
                with open(dest, "wb", buffering=1024*1024) as outf:
                    while True:
                        if self.engine.cancel_flag.is_set(): raise RuntimeError("בוטל")
                        nonce = inf.read(12)
                        if not nonce: break
                        clen = struct.unpack('<I', inf.read(4))[0]
                        ct = inf.read(clen)
                        aad = struct.pack('<Q', chunk_idx)
                        pt = aes.decrypt(nonce, ct, associated_data=aad)
                        if is_compressed: pt = zlib.decompress(pt)
                        outf.write(pt)
                        processed += (12 + 4 + clen)
                        chunk_idx += 1
                        self.update_progress_throttled(processed, f_size)

            self.after(0, lambda: self.log(f"שוחזר: {dest}", "success"))
            self.after(0, lambda: self.show_info("הצלחה", f"הקובץ שוחזר:\n{os.path.basename(dest)}"))

        except Exception as e:
            self.after(0, lambda: self.log(f"שגיאה בפענוח: {e}", "error"))
            self.after(0, lambda: self.show_error("שגיאה", "הפענוח נכשל\n(בדוק את הסיסמה או את הקובץ)"))
        finally: self.after(0, lambda: self.set_busy(False))

if __name__ == "__main__":
    app = HebrewCyberApp()
    app.mainloop()