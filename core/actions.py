import os
import shutil
from datetime import datetime

class MegaActions:
    def __init__(self, quarantine_dir="quarantine"):
        self.quarantine_dir = quarantine_dir
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

    def quarantine_file(self, file_path):
        try:
            file_name = os.path.basename(file_path)
            # ایجاد یک نام امن با تاریخ برای جلوگیری از تداخل
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            new_name = f"{file_name}_{timestamp}.locked"
            dest_path = os.path.join(self.quarantine_dir, new_name)
            
            # انتقال فایل به پوشه قرنطینه
            shutil.move(file_path, dest_path)
            
            # تغییر دسترسی فایل (فقط خواندنی برای امنیت بیشتر)
            os.chmod(dest_path, 0o444) 
            
            return True, dest_path
        except Exception as e:
            return False, str(e)