import yara
import os

class YaraHandler:
    def __init__(self, rules_dir):
        self.rules_dir = rules_dir
        self.rules = None
        self.compile_rules()

    def compile_rules(self):
        rule_files = {}
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            return

        # گشتن توی پوشه‌ها برای پیدا کردن تمام فایل‌های .yar
        for root, dirs, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    full_path = os.path.join(root, file)
                    # استفاده از اسم فایل به عنوان کلید (بدون کاراکترهای خاص)
                    key = file.replace(".", "_").replace("-", "_")
                    rule_files[key] = full_path
        
        if rule_files:
            try:
                self.rules = yara.compile(filepaths=rule_files)
                print(f"[+] موفقیت: {len(rule_files)} فایل قانون یارا آماده شد.")
            except Exception as e:
                print(f"[-] خطا در کامپایل برخی قوانین: {e}")
                print("نکته: بعضی قوانین گیت‌هاب ممکنه به فایل‌های دیگه‌ای نیاز داشته باشن.")

    def scan(self, file_path):
        if not self.rules or not os.path.exists(file_path):
            return None
        try:
            matches = self.rules.match(file_path)
            return matches if matches else None
        except:
            return None