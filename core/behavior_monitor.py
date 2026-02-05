import psutil
import time

class BehaviorMonitor:
    def __init__(self):
        self.suspicious_actions = ["file_infection_attempt", "unauthorized_registry_write"]

    def monitor_process(self, pid):
        """زیر نظر گرفتن یک پروسه خاص برای رفتارهای شبیه Expiro"""
        try:
            proc = psutil.Process(pid)
            print(f"[*] مانیتورینگ پروسه شروع شد: {proc.name()} (PID: {pid})")
            
            # در یک آنتی‌ویروس واقعی، اینجا از Driver استفاده میشه
            # اما ما اینجا دسترسی‌های فایل رو چک می‌کنیم
            for i in range(10): # برای تست ۱۰ ثانیه زیر نظر بگیر
                # چک کردن اینکه آیا پروسه داره فایل‌های زیادی رو باز می‌کنه؟
                files = proc.open_files()
                if len(files) > 50: # اگه یهو ۵۰ تا فایل باز کرد، احتمالاً داره آلوده می‌کنه
                    print(f"[!!!] هشدار: پروسه {proc.name()} در حال دسترسی انبوه به فایل‌هاست!")
                    return "Infector-Like Behavior"
                time.sleep(1)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return "Normal"