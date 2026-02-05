from core.yara_engine import YaraHandler
from core.ai_engine import AIEngine
from core.reporter import MegaReporter # اضافه شد
from core.actions import MegaActions
from core.updater import MegaUpdater
updater = MegaUpdater()
updater.update_rules()
def main():
    print("--- MegaGuard AntiVirus (Phase B + Intelligence) ---")
    
    yara_scanner = YaraHandler("database/rules")
    ai_scanner = AIEngine()
    reporter = MegaReporter(model_name="qwen3:14b") # استفاده از مدل Qwen شما
    
    file_to_scan = input("مسیر فایل برای اسکن را وارد کنید: ")
    
    # اسکن یارا
    yara_result = yara_scanner.scan(file_to_scan)
    if yara_result:
        print(f"[!] خطر قطعی! تشخیص یارا: {yara_result}")
    else:
        # اسکن هوشمند
        # اسکن هوشمند
        features = ai_scanner.get_file_features(file_to_scan)
        score = ai_scanner.get_score(file_to_scan)
        
        # این دو خط زیر رو برای تست اضافه کن:
        print(f"[DEBUG] امتیاز نهایی فایل: {score}")
        print(f"[DEBUG] ویژگی‌های استخراج شده: {features}")
        
        # اگر امتیاز بالای 0.45 بود یا آنتروپی خیلی بالا بود، گزارش بگیر
        if score > 0.45 or (features and features['entropy'] > 7.7):
            print(f"[?] هشدار: فایل نیاز به تحلیل ثانویه دارد (امتیاز: {score})")
            print("\n[....] در حال ارسال جزئیات فنی به Qwen3:14b...")
            
            report = reporter.get_ai_analysis(file_to_scan, features, score)
            print("-" * 30)
            print("گزارش هوش مصنوعی:")
            print(report)
            print("-" * 30)
        else:
            print("[+] فایل از نظر ما پاک است.")

        choice = input("\n[!] آیا می‌خواهید این فایل را قرنطینه کنید؟ (y/n): ").lower()
        if choice == 'y':
            actions = MegaActions()
            success, result = actions.quarantine_file(file_to_scan)
            if success:
                print(f"[+] فایل با موفقیت به قرنطینه منتقل شد: {result}")
            else:
                print(f"[-] خطا در قرنطینه: {result}")
        else:
                print("[*] فایلی منتقل نشد. مراقب باشید!")

if __name__ == "__main__":
    main()