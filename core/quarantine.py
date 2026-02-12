import os
import base64

class QuarantineManager:
    def __init__(self):
        self.q_path = "quarantine_zone"
        if not os.path.exists(self.q_path):
            os.makedirs(self.q_path)

    def isolate_file(self, file_path):
        """قرنطینه بدون نیاز به کتابخانه خارجی (با استفاده از Base64)"""
        try:
            file_name = os.path.basename(file_path)
            safe_path = os.path.join(self.q_path, f"{file_name}.locked")
            
            # خواندن فایل و تبدیل به Base64 (برای غیرقابل اجرا شدن)
            with open(file_path, "rb") as f:
                content = f.read()
                # یک لایه تغییر ساده برای از کار انداختن بدافزار
                encoded = base64.b64encode(content[::-1]) 
            
            with open(safe_path, "wb") as f:
                f.write(encoded)
            
            os.remove(file_path) # حذف فایل اصلی
            return True, safe_path
        except Exception as e:
            return False, str(e)