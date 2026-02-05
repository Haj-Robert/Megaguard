import customtkinter as ctk
from tkinter import messagebox, filedialog
import os
import threading
from core.scanner import MegaScanner
from core.updater import MegaUpdater
class MegaGuardGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("MegaGuard AI Security 2026")
        self.geometry("950x650")
        ctk.set_appearance_mode("dark")
        
        self.scanner = MegaScanner()
        
        # Layout
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
        
        # --- Main Dashboard ---
        self.main = ctk.CTkFrame(self, corner_radius=20, fg_color="#121212")
        self.main.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

        self.header = ctk.CTkLabel(self.main, text="پنل آنالیز و پایش هوشمند", font=("Segoe UI", 24))
        self.header.pack(pady=25)
        
        self.log_box = ctk.CTkTextbox(self.main, width=650, height=350, font=("Consolas", 12))
        self.log_box.pack(padx=25, pady=10)

        self.actions = ctk.CTkFrame(self.main, fg_color="transparent")
        self.actions.pack(pady=20)
        self.updater = MegaUpdater()
        self.btn_update = ctk.CTkButton(self.sidebar, text="🔄 آپدیت دیتابیس", 
                                 command=self.run_update, fg_color="#27ae60")
        self.btn_update.pack(pady=10)
        self.btn_scan = ctk.CTkButton(self.actions, text="اسکن عمیق فایل", 
                                      command=self.manual_scan, width=200, height=45, corner_radius=10)
        self.btn_scan.grid(row=0, column=0, padx=10)
        self.btn_proc = ctk.CTkButton(self.actions, text="اسکن پردازش‌های فعال", 
                                command=self.scan_processes, fg_color="#d35400")
        self.btn_proc.grid(row=0, column=2, padx=10)
        self.btn_clear = ctk.CTkButton(self.actions, text="پاکسازی لاگ", 
                                       command=lambda: self.log_box.delete("1.0", "end"), 
                                       width=120, height=45, fg_color="gray30")
        self.btn_clear.grid(row=0, column=1, padx=10)
        self.btn_quarantine = ctk.CTkButton(self.actions, text="مدیریت قرنطینه", 
                                     command=self.show_quarantine, fg_color="#2c3e50", width=150)
        self.btn_quarantine.grid(row=0, column=3, padx=10)
        self.btn_net = ctk.CTkButton(self.actions, text="پایش شبکه", 
                                  command=self.show_network_monitor, fg_color="#8e44ad", width=150)
        self.btn_net.grid(row=1, column=0, padx=10, pady=10) # در ردیف دوم چیدمان کن
        self.btn_report = ctk.CTkButton(self.actions, text="📥 خروجی گزارش", 
                                 command=self.save_report, fg_color="#16a085", width=150)
        self.btn_report.grid(row=1, column=1, padx=10, pady=10)
        self.btn_deep_scan = ctk.CTkButton(self.actions, text="🛡️ اسکن عمیق (Cloud)", 
                                   command=self.start_deep_scan, fg_color="#c0392b", width=150)
        self.btn_deep_scan.grid(row=1, column=2, padx=10, pady=10)
        # این تابع رو حتماً داخل کلاس MegaGuardGUI بنویس

    def start_deep_scan(self):
        path = filedialog.askopenfilename()
        if path:
            self.log_box.insert("end", f"\n[🚀] شروع اسکن عمیق ابری برای: {os.path.basename(path)}...\n", "yellow")
        
            def task():
                result = self.scanner.deep_scan_online(path)
                if isinstance(result, int):
                    color = "red" if result > 0 else "green"
                    self.log_box.insert("end", f"[📊] نتیجه دیتابیس جهانی: {result} آنتی‌ویروس این فایل را مخرب تشخیص دادند.\n", color)
                    if result > 5:
                        self.scanner.isolate_file(path)
                        self.log_box.insert("end", "[🔒] فایل به دلیل ریسک بالا قرنطینه شد.\n")
                else:
                    self.log_box.insert("end", f"[!] {result}\n")
        
        threading.Thread(target=task).start()

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
        if self.monitor_switch.get() == 1:
            watch_path = os.path.expanduser("~\\Downloads")
            self.scanner.start_monitoring(watch_path, self.on_detection)
            self.status_dot.configure(text_color="#00ff00")
            self.status_text.configure(text="تحت حفاظت زنده")
            self.log_box.insert("end", f"[+] مانیتورینگ زنده فعال شد: {watch_path}\n", "green")
        else:
            self.scanner.stop_monitoring()
            self.status_dot.configure(text_color="red")
            self.status_text.configure(text="سیستم بی‌دفاع")
            self.log_box.insert("end", "[-] مانیتورینگ متوقف شد.\n", "yellow")

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
        path = filedialog.askopenfilename()
        if path:
            res = self.scanner.scan_file(path)
            self.log_box.insert("end", f"\n[*] اسکن دستی: {os.path.basename(path)}\n")
            self.log_box.insert("end", f"   >> نتیجه: {res['status']} ({int(res['score']*100)}%)\n")
            if res['findings']:
                self.log_box.insert("end", f"   >> یافته‌ها: {', '.join(res['findings'])}\n")
            
            if res['score'] > 0.6:
                if messagebox.askyesno("تایید قرنطینه", "این فایل خطرناک است. قرنطینه شود؟"):
                    self.scanner.isolate_file(path)
                    self.log_box.insert("end", "[+] فایل با موفقیت ایزوله شد.\n")
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

if __name__ == "__main__":
    app = MegaGuardGUI()
    app.mainloop()