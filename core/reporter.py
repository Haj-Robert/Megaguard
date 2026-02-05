import requests
import json

class MegaReporter:
    def __init__(self, model_name="qwen3:14b"):
        self.model_name = model_name
        self.url = "http://localhost:11434/api/generate"

    def get_ai_analysis(self, file_path, features, score):
        if not features:
            return "خطا: ویژگی‌های فایل استخراج نشده است."

        prompt = f"""
        فایلی با مشخصات زیر توسط آنتی‌ویروس شناسایی شده:
        - مسیر: {file_path}
        - امتیاز خطر: {score}
        - آنتروپی: {features.get('entropy', 0):.2f}
        - تعداد توابع خطرناک: {features.get('critical_api_count', 0)}
        
        به عنوان یک متخصص امنیت، به زبان فارسی بگو چرا این فایل خطرناک به نظر می‌رسد؟ (در حد یک یا دو جمله خیلی کوتاه)
        """

        try:
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "stream": False
            }
            
            # نمایش پیغام برای اینکه بدونی مدل در حال پردازش هست
            print(f"[...] مدل {self.model_name} در حال تحلیل است. لطفا شکیبا باشید (این کار ممکن است ۱-۲ دقیقه طول بکشد)...")
            
            # timeout=None یعنی زمان نامحدود
            response = requests.post(self.url, json=payload, timeout=None) 
            
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "مدل پاسخی تولید نکرد.").strip()
            else:
                return f"خطای Ollama: {response.status_code}"
                
        except Exception as e:
            return f"خطا در ارتباط: {str(e)}"