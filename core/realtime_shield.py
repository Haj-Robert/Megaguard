from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os

class DownloadHandler(FileSystemEventHandler):
    def __init__(self, scanner, log_callback):
        self.scanner = scanner
        self.log_callback = log_callback

    def on_created(self, event):
        if event.is_directory:
            return
        
        file_path = event.src_path
        # یک وقفه کوتاه برای اینکه فایل کامل روی دیسک نوشته بشه
        time.sleep(2) 
        
        self.log_callback(f"[⚡] سپر لحظه‌ای: شناسایی فایل جدید -> {os.path.basename(file_path)}")
        
        # اجرای اسکن هوشمند
        try:
            status, findings = self.scanner.scan_file_intelligent(file_path)
            
            if status == "RED":
                self.log_callback(f"[🛑] خطر! فایل مخرب بلافاصله مسدود شد.")
                self.scanner.quarantine_file(file_path)
            elif status == "YELLOW":
                self.log_callback(f"[⚠️] هشدار: فایل مشکوک است. بررسی دستی پیشنهاد می‌شود.")
        except Exception as e:
            self.log_callback(f"[!] خطای سپر لحظه‌ای: {str(e)}")

    def on_moved(self, event):
        # اگه فایلی از جای دیگه کات شد توی پوشه دانلود، باز هم اسکنش کن
        if not event.is_directory:
            self.on_created(event)