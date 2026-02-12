import psutil
import threading
import time
import os

class ProcessMonitor:
    def __init__(self, scanner_instance, log_callback):
        self.scanner = scanner_instance
        self.log_callback = log_callback
        self.running = True

    def start(self):
        """شروع پایش پردازش‌ها در یک ترد جداگانه"""
        def monitor():
            # یک وقفه کوتاه برای لود شدن کامل GUI
            time.sleep(3)
            self.log_callback("[🚀] موتور دیده‌بان زنده (Active Shield) فعال شد.")
            
            # ثبت پردازش‌های فعلی برای اینکه فقط جدیدها رو اسکن کنیم
            existing_pids = set(p.pid for p in psutil.process_iter())

            while self.running:
                try:
                    current_pids = set(p.pid for p in psutil.process_iter())
                    new_pids = current_pids - existing_pids

                    for pid in new_pids:
                        try:
                            proc = psutil.Process(pid)
                            proc_path = proc.exe()
                            
                            # نادیده گرفتن پردازش‌های ویندوز و خودِ پایتون
                            if "System32" in proc_path or "Microsoft" in proc_path or "python" in proc_path.lower():
                                continue

                            # اسکن هوشمند فایلِ پردازش
                            status, findings = self.scanner.scan_file_intelligent(proc_path)
                            
                            if status == "RED":
                                self.log_callback(f"[🛑] هشدار امنیتی: برنامه مخرب مسدود شد -> {proc.name()}")
                                proc.terminate() # کشتن آنی پردازش
                            
                        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                            continue

                    existing_pids = current_pids
                    time.sleep(2) # هر ۲ ثانیه چک کن
                except Exception as e:
                    print(f"Monitor Error: {e}")

        threading.Thread(target=monitor, daemon=True).start()