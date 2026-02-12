import os
import zipfile
import pandas as pd
import joblib
from core.ai_engine import AIEngine

def train_mega_guard():
    # مسیرها (مطمئن شو این مسیرها روی سیستم درسته)
    malware_path = r"C:\MG_Lab\theZoo-master\malware\Binaries"
    benign_path = r"C:\Windows\System32"
    
    engine = AIEngine()
    dataset = []
    
    print("--- شروع آموزش پیشرفته MegaGuard (Strings + Signatures) ---")

    # فاز ۱: بدافزارها
    mal_count = 0
    for root, dirs, files in os.walk(malware_path):
        for file in files:
            if mal_count >= 300: break # تعداد نمونه برای آموزش
            if file.lower().endswith(".zip"):
                try:
                    with zipfile.ZipFile(os.path.join(root, file), 'r') as z:
                        for name in z.namelist():
                            if name.endswith('/'): continue
                            with z.open(name, pwd=b"infected") as f:
                                data = f.read()
                                feats = engine.get_file_features(data=data)
                                if feats:
                                    row = [feats['entropy'], feats['num_sections'], 
                                           feats['critical_api_count'], feats['is_signed'],
                                           feats['string_risk_score'], feats['is_packed'], 1]
                                    dataset.append(row)
                                    mal_count += 1
                                    print(f"   [OK] بدافزار {mal_count}: {name}")
                except: continue

    # فاز ۲: فایل‌های سالم
    print(f"\n[*] استخراج فایل‌های سالم...")
    benign_count = 0
    for root, dirs, files in os.walk(benign_path):
        if benign_count >= mal_count: break
        for file in files:
            if file.lower().endswith(('.exe', '.dll')):
                feats = engine.get_file_features(file_path=os.path.join(root, file))
                if feats:
                    row = [feats['entropy'], feats['num_sections'], 
                           feats['critical_api_count'], feats['is_signed'],
                           feats['string_risk_score'], feats['is_packed'], 0]
                    dataset.append(row)
                    benign_count += 1
                    if benign_count % 50 == 0: print(f"   [OK] {benign_count} فایل سالم...")
            if benign_count >= mal_count: break

    # فاز ۳: ساخت مدل
    if not dataset:
        print("[-] داده‌ای پیدا نشد!")
        return

    cols = ['entropy', 'num_sections', 'critical_api_count', 'is_signed', 'string_risk_score', 'is_packed', 'label']
    df = pd.DataFrame(dataset, columns=cols)
    X = df.drop('label', axis=1)
    y = df['label']
    
    model = engine.train_with_cv(X, y)
    
    if not os.path.exists("database"): os.makedirs("database")
    joblib.dump(model, "database/mega_model.pkl")
    print("\n[!] مدل جدید با موفقیت ساخته شد.")

if __name__ == "__main__":
    train_mega_guard()