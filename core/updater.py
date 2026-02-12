import requests
import json
import os

class MegaUpdater:
    def __init__(self, db_path="database/db.json"):
        self.db_path = db_path
        # یکی از منابع معتبر برای دریافت هش‌های جدید (به عنوان نمونه)
        self.source_url = "https://raw.githubusercontent.com/u104/malware-signatures/master/md5.txt"

    def update_db(self):
        try:
            print("[#] در حال دریافت آخرین امضاهای دیجیتال...")
            response = requests.get(self.source_url, timeout=10)
            if response.status_color == 200:
                new_hashes = response.text.splitlines()
                
                # لود کردن دیتابیس فعلی
                if os.path.exists(self.db_path):
                    with open(self.db_path, "r") as f:
                        data = json.load(f)
                else:
                    data = {"virus_signatures": {}}

                # اضافه کردن هش‌های جدید
                count = 0
                for h in new_hashes:
                    if h not in data["virus_signatures"]:
                        data["virus_signatures"][h] = "New_Detected_Malware"
                        count += 1
                
                # ذخیره دیتابیس آپدیت شده
                with open(self.db_path, "w") as f:
                    json.dump(data, f, indent=4)
                
                return f"آپدیت موفق! {count} ویروس جدید به لیست سیاه اضافه شد."
            return "خطا در اتصال به سرور آپدیت."
        except Exception as e:
            return f"Error: {str(e)}"