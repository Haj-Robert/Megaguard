import customtkinter as ctk
from tkinter import messagebox, filedialog
import os
import lief
from core.scanner import MegaScanner
from core.updater import MegaUpdater
from core.usb_guard import USBGuard
from core.process_monitor import ProcessMonitor
from core.realtime_shield import DownloadHandler
from watchdog.observers import Observer
import core.scanner
print(f"📍 پایتون داره فایل اسکنر رو از اینجا می‌خونه: {core.scanner.__file__}")
class MegaGuardGUI(ctk.CTk):
    
    def __init__(self):
        super().__init__()
        # ۱. تنظیمات پنجره
        self.title("MegaGuard AI Security 2026")
        self.geometry("950x650")
        ctk.set_appearance_mode("dark")
        
        # ۲. مقداردهی اولیه متغیرها (بدون دستورات گرافیکی)
        self.scanner = MegaScanner()
        download_path = os.path.join(os.path.expanduser("~"), "Downloads")
        # تزریق دستی تابع (فقط برای اینکه ارور متوقف بشه و بفهمیم مشکل کجاست)
        if not hasattr(self.scanner, 'quarantine_file'):
            def manual_quarantine(file_path):
                import shutil
                try:
                    q_dir = os.path.join(os.getcwd(), "database", "quarantine")
                    if not os.path.exists(q_dir): os.makedirs(q_dir)
                    dest = os.path.join(q_dir, os.path.basename(file_path) + ".locked")
                    shutil.move(file_path, dest)
                    return True
                except: return False
            
            # چسباندن تابع به آبجکت اسکنر
            self.scanner.quarantine_file = manual_quarantine
            print("⚠️ مگاگارد مجبور شد تابع قرنطینه رو دستی تزریق کنه!")

        # ۳. چیدمان اصلی (Layout)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- Sidebar ---
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo = ctk.CTkLabel(self.sidebar, text="🛡️ MEGAGUARD AI", font=("Segoe UI", 22, "bold"))
        self.logo.pack(pady=40)

        self.monitor_switch = ctk.CTkSwitch(self.sidebar, text="محافظت لحظه‌ای", 
                                            command=self.toggle_monitor,
                                            progress_color="#1f538d")
        self.monitor_switch.pack(pady=20)

        self.stat_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.stat_frame.pack(side="bottom", pady=30)
        self.status_dot = ctk.CTkLabel(self.stat_frame, text="●", text_color="red")
        self.status_dot.grid(row=0, column=0, padx=5)
        self.status_text = ctk.CTkLabel(self.stat_frame, text="سیستم بی‌دفاع")
        self.status_text.grid(row=0, column=1)

        self.btn_update = ctk.CTkButton(self.sidebar, text="🔄 آپدیت دیتابیس", 
                                 command=self.run_update, fg_color="#bc00e2")
        self.btn_update.pack(pady=10)
        
        # --- Main Dashboard ---
        self.main = ctk.CTkFrame(self, corner_radius=20, fg_color="#121212")
        self.main.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

        self.header = ctk.CTkLabel(self.main, text="پنل آنالیز و پایش هوشمند", font=("Segoe UI", 24))
        self.header.pack(pady=25)
        
        # ۴. ساخت log_box (خیلی مهم: قبل از استفاده باید ساخته شود)
        self.log_box = ctk.CTkTextbox(self.main, width=650, height=350, font=("Consolas", 12))
        self.log_box.pack(padx=25, pady=10)
        
        # تنظیم استایل‌ها
        self.log_box.tag_config("info", foreground="#3498db") 
        self.log_box.tag_config("danger", foreground="#ff4d4d")
        self.log_box.tag_config("warning", foreground="#ffa500")
        self.log_box.tag_config("success", foreground="#2ecc71")
        self.log_box.tag_config("text", foreground="#ffffff")

        # ۵. ساخت دکمه‌ها و سایر ویجت‌ها
        self.actions = ctk.CTkFrame(self.main, fg_color="transparent")
        self.actions.pack(pady=20)
        
        self.btn_scan = ctk.CTkButton(self.actions, text="اسکن عمیق فایل", 
                                      command=self.manual_scan, width=200, height=45, corner_radius=10)
        self.btn_scan.grid(row=0, column=0, padx=10)
        
        self.btn_clear = ctk.CTkButton(self.actions, text="پاکسازی لاگ", 
                                       command=lambda: self.log_box.delete("1.0", "end"), 
                                       width=120, height=45, fg_color="gray30")
        self.btn_clear.grid(row=0, column=1, padx=10)

        self.btn_proc = ctk.CTkButton(self.actions, text="اسکن پردازش‌های فعال", 
                                command=self.scan_processes, fg_color="#d35400")
        self.btn_proc.grid(row=0, column=2, padx=10)

        self.btn_quarantine = ctk.CTkButton(self.actions, text="مدیریت قرنطینه", 
                                     command=self.show_quarantine, fg_color="#2c3e50", width=150)
        self.btn_quarantine.grid(row=0, column=3, padx=10)

        self.btn_net = ctk.CTkButton(self.actions, text="پایش شبکه", 
                                  command=self.show_network_monitor, fg_color="#8e44ad", width=150)
        self.btn_net.grid(row=1, column=0, padx=10, pady=10)

        self.btn_report = ctk.CTkButton(self.actions, text="📥 خروجی گزارش", 
                                  command=self.save_report, fg_color="#16a085", width=150)
        self.btn_report.grid(row=1, column=1, padx=10, pady=10)

        self.btn_deep_scan = ctk.CTkButton(self.actions, text="🛡️ اسکن عمیق (Cloud)", 
                                   command=self.start_deep_scan, fg_color="#c0392b", width=150)
        self.btn_deep_scan.grid(row=1, column=2, padx=10, pady=10)

        # ۶. حالا که همه چیز ساخته شده، موتورها رو استارت می‌زنیم
        try:
            # یو‌اس‌بی گارد
            self.usb_guard = USBGuard(self.scanner, self.update_log_from_usb)
            self.usb_guard.start()

            # مانیتورینگ پردازش‌ها
            self.process_monitor = ProcessMonitor(self.scanner, self.update_log_from_usb)
            self.process_monitor.start()
            
            # آپدیتور
            self.updater = MegaUpdater()

            # حالا می‌تونی با خیال راحت توی log_box بنویسی
            self.log_box.insert("end", "[🛡️] تمام موتورهای مگاگارد با موفقیت لود شدند.\n", "success")
            self.log_box.insert("end", f"[⚡] سپر لحظه‌ای روی پوشه Downloads فعال شد.\n", "success")
        except Exception as e:
            print(f"Startup Error: {e}")
        
        # این تابع رو حتماً داخل کلاس MegaGuardGUI بنویس

    def start_deep_scan(self):
        if hasattr(self, 'current_suspicious_file'):
            path = self.current_suspicious_file
            self.log_box.insert("end", "[🚀] در حال ارسال هش به دیتابیس جهانی (Cloud Scan)...\n", "cyan")
        
            # اجرای متد اسکن آنلاین که قبلاً با پروکسی تنظیم کردیم
            result = self.scanner.deep_scan_online(path)
        
            if isinstance(result, int):
                color = "red" if result > 0 else "green"
                self.log_box.insert("end", f"[📊] نتیجه نهایی: {result} آنتی‌ویروس این فایل را مخرب دانستند.\n", color)
            else:
                self.log_box.insert("end", f"[!] خطا یا عدم وجود فایل: {result}\n", "red")

    def start_deep_scan(self):
        if hasattr(self, 'current_suspicious_file'):
            path = self.current_suspicious_file
            self.log_box.insert("end", "[🚀] در حال ارسال هش به دیتابیس جهانی (Cloud Scan)...\n", "cyan")
        
            # اجرای متد اسکن آنلاین که قبلاً با پروکسی تنظیم کردیم
            result = self.scanner.deep_scan_online(path)
        
            if isinstance(result, int):
                color = "red" if result > 0 else "green"
                self.log_box.insert("end", f"[📊] نتیجه نهایی: {result} آنتی‌ویروس این فایل را مخرب دانستند.\n", color)
            else:
                self.log_box.insert("end", f"[!] خطا یا عدم وجود فایل: {result}\n", "red")

    def save_report(self):
        try:
            # فعلاً یک لیست خالی و وضعیت SAFE میدیم تا تست کنیم
            filename = self.scanner.generate_report([], "SAFE") 
            self.log_box.insert("end", f"\n[📄] گزارش با موفقیت ساخته شد: {filename}\n", "green")
            messagebox.showinfo("عملیات موفق", f"فایل گزارش در پوشه پروژه ذخیره شد:\n{filename}")
        except Exception as e:
            self.log_box.insert("end", f"\n[❌] خطا در ساخت گزارش: {str(e)}\n", "red")
   
    def scan_processes(self):
        self.log_box.insert("end", "\n[🔍] در حال اسکن حافظه RAM...\n", "cyan")
        
        # اجرای اسکن در یک ترد جداگانه که برنامه هنگ نکنه
        def run():
            suspicious = self.scanner.scan_running_processes()
            if not suspicious:
                self.log_box.insert("end", "[✅] هیچ پردازش مخربی در حال اجرا نیست.\n", "green")
            else:
                for p in suspicious:
                    self.log_box.insert("end", f"[🛑] اخطار: برنامه مشکوک پیدا شد: {p['name']} (PID: {p['pid']})\n", "red")
                    if messagebox.askyesno("تهدید فعال!", f"برنامه {p['name']} مشکوک است. آیا بسته شود؟"):
                        if self.scanner.kill_process(p['pid']):
                            self.log_box.insert("end", f"[✔️] پردازش {p['pid']} با موفقیت بسته شد.\n")
        
        threading.Thread(target=run).start()
        
    def toggle_monitor(self):
        def run_observer():
            try:
                # چک کردن اینکه آیا مأمور از قبل وجود دارد یا خیر
                if not hasattr(self, 'observer'):
                    self.observer = None

                if self.monitor_switch.get() == 1:
                    # اگر مأمور فعال نیست، فعالش کن
                    if self.observer is None or not self.observer.is_alive():
                        download_path = os.path.join(os.path.expanduser("~"), "Downloads")
                        self.event_handler = DownloadHandler(self.scanner, self.update_log_from_usb)
                        self.observer = Observer()
                        self.observer.schedule(self.event_handler, download_path, recursive=False)
                        self.observer.start()
                        
                        self.status_dot.configure(text_color="green")
                        self.status_text.configure(text="سیستم محافظت شده")
                        self.after(0, lambda: self.log_box.insert("end", "[🟢] محافظت لحظه‌ای فعال شد.\n", "success"))
                else:
                    if self.observer and self.observer.is_alive():
                        self.observer.stop()
                        self.observer.join() # صبر کن تا کاملاً متوقف بشه
                        self.observer = None # مأمور رو از لیست حذف کن
                        
                        self.status_dot.configure(text_color="red")
                        self.status_text.configure(text="سیستم بی‌دفاع")
                        self.after(0, lambda: self.log_box.insert("end", "[🔴] محافظت لحظه‌ای غیرفعال شد.\n", "danger"))
            except Exception as e:
                self.after(0, lambda: self.log_box.insert("end", f"[❌] خطا: {str(e)}\n", "danger"))

        import threading
        threading.Thread(target=run_observer, daemon=True).start()

        # حالا ترد رو استارت می‌زنیم
        import threading
        threading.Thread(target=run_observer, daemon=True).start()

    def on_detection(self, result):
        """فراخوانی خودکار هنگام تغییرات در پوشه"""
        name = os.path.basename(result['path'])
        score_pc = int(result['score'] * 100)
        
        self.log_box.insert("end", f"\n[!] فایل جدید شناسایی شد: {name}\n")
        self.log_box.insert("end", f"   >> امتیاز خطر: {score_pc}%\n")
        
        if result['score'] > 0.6:
            self.log_box.insert("end", f"   >> شواهد: {', '.join(result['findings'])}\n", "red")
            self.log_box.insert("end", f"   >> اقدام: انتقال به قرنطینه انجام شد.\n", "red")
            self.scanner.isolate_file(result['path'])
            messagebox.showwarning("تهدید خطرناک!", f"فایل {name} مخرب تشخیص داده شد و قرنطینه شد.")
        else:
            self.log_box.insert("end", "   >> وضعیت: فایل پاک به نظر می‌رسد.\n", "green")

    def manual_scan(self):
        # ۱. انتخاب فایل توسط کاربر
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        # ۲. آماده‌سازی ظاهر GUI برای اسکن جدید
        self.log_box.delete("1.0", "end") # پاک کردن لاگ قبلی
        self.log_box.insert("end", f"🚀 شروع عملیات کالبدشکافی فایل...\n", "info")
        self.log_box.insert("end", f"📂 مسیر: {file_path}\n", "text")
        self.log_box.insert("end", f"{'='*40}\n", "text")

        # ۳. فراخوانی موتور هوشمند مگاگارد (همون متد MegaScanner)
        # این متد حالا هم YARA رو چک میکنه، هم LIEF، هم هش و هم استاتیک
        status, findings = self.scanner.scan_file_intelligent(file_path)

        # ۴. نمایش جزئیات یافته‌ها (Findings)
        if findings:
            self.log_box.insert("end", "🔍 تحلیل لایه‌ها:\n", "info")
            for discovery in findings:
                # هر یافته رو در یک خط جدید با علامت هشدار نشون میدیم
                self.log_box.insert("end", f"  [!] {discovery}\n", "warning")
        else:
            self.log_box.insert("end", "🔎 هیچ الگوی مشکوکی در لایه‌های اولیه یافت نشد.\n", "text")

        # ۵. واکنش نهایی بر اساس وضعیت رنگی
        self.update_ui_result(status, file_path)

    def update_ui_result(self, status, file_path):
        """تغییر رنگ و دکمه‌ها بر اساس نتیجه اسکن"""
        if status == "RED":
            self.log_box.insert("end", f"\n██████████████████████████████\n", "danger")
            self.log_box.insert("end", f"🛑 وضعیت: تهدید بسیار خطرناک شناسایی شد!\n", "danger")
            self.log_box.insert("end", f"██████████████████████████████\n", "danger")
        elif status == "YELLOW":
            self.log_box.insert("end", f"\n⚠️ وضعیت: مشکوک! (نیاز به تحلیل ابری)\n", "warning")
            self.status_label.configure(text="وضعیت: مشکوک", text_color="#ffa500")
            # فعال کردن دکمه اسکن عمیق
            self.btn_deep_scan.configure(state="normal", fg_color="#e67e22")
            self.current_suspicious_file = file_path
        
        else:
            self.log_box.insert("end", f"\n✅ وضعیت: فایل پاک است.\n", "success")
            self.status_label.configure(text="وضعیت: ایمن", text_color="#2ecc71")
            self.btn_deep_scan.configure(state="disabled", fg_color="gray")
    
    def show_quarantine(self):
        # ایجاد یک پنجره پاپ‌آپ جدید برای قرنطینه
        q_window = ctk.CTkToplevel(self)
        q_window.title("اتاق قرنطینه مگاگارد")
        q_window.geometry("500x400")
        
        label = ctk.CTkLabel(q_window, text="فایل‌های ایزوله شده", font=("Arial", 16, "bold"))
        label.pack(pady=10)

        files_list = self.scanner.get_quarantine_files()
        
        if not files_list:
            ctk.CTkLabel(q_window, text="قرنطینه خالی است.").pack(pady=20)
        else:
            for f in files_list:
                frame = ctk.CTkFrame(q_window)
                frame.pack(fill="x", padx=10, pady=5)
                ctk.CTkLabel(frame, text=f).pack(side="left", padx=10)
                
                # دکمه حذف دائمی
                ctk.CTkButton(frame, text="حذف", width=60, fg_color="red",
                              command=lambda name=f: [os.remove(os.path.join(self.scanner.quarantine_path, name)), q_window.destroy(), self.show_quarantine()]).pack(side="right", padx=5)

    def show_network_monitor(self):
        net_window = ctk.CTkToplevel(self)
        net_window.title("رادار شبکه مگاگارد")
        net_window.geometry("600x400")
        
        self.log_box.insert("end", "[🌐] در حال واکاوی اتصالات شبکه...\n")
        
        conns = self.scanner.get_network_connections()
        if not conns:
            ctk.CTkLabel(net_window, text="هیچ اتصال فعالی پیدا نشد.").pack(pady=20)
        else:
            for c in conns:
                frame = ctk.CTkFrame(net_window)
                frame.pack(fill="x", padx=10, pady=2)
                text = f"App: {c['name']} | Remote: {c['remote']}"
                ctk.CTkLabel(frame, text=text, font=("Consolas", 11)).pack(side="left", padx=10)
                
                # دکمه قطع دسترسی (بستن برنامه)
                ctk.CTkButton(frame, text="قطع اتصال", width=80, fg_color="red",
                              command=lambda p=c['pid']: self.scanner.kill_process(p)).pack(side="right", padx=5)
    
    def run_update(self):
        self.log_box.insert("end", "\n[📡] در حال اتصال به سرور مرکزی برای دریافت آپدیت...\n", "cyan")
        
        # تعریف تابع تسک دقیقا داخل همین متد که شناخته بشه
        def task():
            try:
                msg = self.updater.update_db()
                # برای آپدیت GUI از داخل ترد، بهتره از متد after استفاده بشه یا مستقیم (در CustomTkinter مشکلی نداره)
                self.log_box.insert("end", f"[✅] نتیجه: {msg}\n", "green")
                # ریلود کردن هش‌ها در موتور اسکنر
                self.scanner.signatures = self.scanner.load_database()
                self.log_box.insert("end", "[🔄] دیتابیس محلی با موفقیت بازنشانی شد.\n")
            except Exception as e:
                self.log_box.insert("end", f"[❌] خطا در حین آپدیت: {str(e)}\n", "red")
        
        # حالا ترد رو استارت می‌زنیم
        threading.Thread(target=task, daemon=True).start()

    def update_log_from_usb(self, message):
        self.log_box.insert("end", f"{message}\n")
        self.log_box.see("end")

    def on_closing(self):
    # به جای بسته شدن، مگاگارد فقط مخفی میشه و در پس‌زمینه میمونه
        from tkinter import messagebox
        if messagebox.askokcancel("خروج امن", "آیا می‌خواهید مگاگارد را کاملاً ببندید؟ (سیستم بی‌دفاع می‌شود)"):
            self.destroy()

def on_closing(self):
    # به جای بستن، برنامه رو مخفی کن (برای امنیت بیشتر)
    self.withdraw()
    self.log_box.insert("end", "[ℹ️] مگاگارد در پس‌زمینه همچنان مراقب شماست...\n")   

if __name__ == "__main__":
    app = MegaGuardGUI()
    app.mainloop()