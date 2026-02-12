import os
import math
import joblib
import pefile
import re
import json
import hashlib
import numpy as np
import ctypes
from ctypes import wintypes

class AIEngine:
    def __init__(self):
        # تنظیمات پایه
        self.critical_apis = ['createremotethread', 'virtualallocex', 'writeprocessmemory', 'setwindowshookex']
        self.mal_strings = [r'http://', r'https://', r'powershell', r'cmd.exe', r'eval\(', r'base64']
        
        # مسیرهای دیتابیس
        self.model_path = "database/mega_model.pkl"
        self.trust_db_path = "database/trust_db.json"
        
        # ۱. لود دیتابیس اعتماد (Memory)
        self.trust_db = self.load_trust_db()
        
        # ۲. لود مدل AI
        self.model = None
        self.load_model()

    def load_trust_db(self):
        """بارگذاری حافظه اسکن‌های قبلی"""
        if os.path.exists(self.trust_db_path):
            try:
                with open(self.trust_db_path, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {"hashes": {}}

    def save_trust_db(self):
        """ذخیره وضعیت جدید در دیتابیس اعتماد"""
        if not os.path.exists("database"):
            os.makedirs("database")
        with open(self.trust_db_path, 'w') as f:
            json.dump(self.trust_db, f)

    def load_model(self):
        """لود کردن مدل آموزش دیده Random Forest"""
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                print("[+] مدل هوشمند MegaGuard با موفقیت لود شد.")
        except Exception as e:
            print(f"[-] خطا در بارگذاری مدل AI: {e}")

    def verify_signature(self, file_path):
        """بررسی اعتبار امضای دیجیتال از طریق API ویندوز"""
        # تعریف ساختار GUID چون ctypes ممکنه مستقیم نداشته باشه
        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", wintypes.BYTE * 8),
            ]
            def __init__(self, guid_str):
                # تبدیل رشته GUID به ساختار عددی
                import uuid
                data = uuid.UUID(guid_str)
                self.Data1 = data.time_low
                self.Data2 = data.time_mid
                self.Data3 = data.time_hi_version
                self.Data4 = (ctypes.c_byte * 8)(*data.bytes[8:])

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                        ("hPtr", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                        ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                        ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)), ("dwStateAction", wintypes.DWORD),
                        ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                        ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD)]

        # شناسه استاندارد برای تایید امضای فایل
        WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID("{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}")
        
        file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), file_path, None, None)
        data = WINTRUST_DATA(cbStruct=ctypes.sizeof(WINTRUST_DATA), dwUIChoice=2, fdwRevocationChecks=0,
                             dwUnionChoice=1, pFile=ctypes.pointer(file_info), dwStateAction=1)

        try:
            result = ctypes.windll.wintrust.WinVerifyTrust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(data))
            return result == 0
        except:
            return False

    def calculate_entropy(self, data):
        """محاسبه میزان پیچیدگی فایل (برای تشخیص فایل‌های رمز شده یا پکرها)"""
        if not data: return 0
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probs = counts[counts > 0] / len(data)
        return -np.sum(probs * np.log2(probs))

    def extract_strings_risk(self, data):
        """بررسی وجود کلمات خطرناک در کدهای برنامه"""
        count = 0
        try:
            text = data.decode('ascii', errors='ignore').lower()
            for pattern in self.mal_strings:
                count += len(re.findall(pattern, text))
        except: pass
        return count

    def get_file_features(self, file_path=None, data=None):
        """استخراج ویژگی‌های فنی فایل PE"""
        try:
            if not data and file_path:
                with open(file_path, "rb") as f: data = f.read()
            if not data or not data.startswith(b'MZ'): return None

            pe = pefile.PE(data=data, fast_load=True)
            features = {
                'entropy': self.calculate_entropy(data),
                'num_sections': len(pe.sections),
                'critical_api_count': 0,
                'is_signed': 1 if pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress != 0 else 0,
                'string_risk_score': self.extract_strings_risk(data),
                'is_packed': 0
            }

            # تشخیص پکرها
            for section in pe.sections:
                try:
                    name = section.Name.decode().strip('\x00').upper()
                    if any(p in name for p in ["UPX", "PACK", "VMP", "PROTECT"]):
                        features['is_packed'] = 1
                except: continue
            
            # شمارش APIهای حساس
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode().lower()
                            if any(api in name for api in self.critical_apis):
                                features['critical_api_count'] += 1
            pe.close()
            return features
        except: return None

    def get_score(self, file_path):
        """تابع اصلی برای تعیین امتیاز نهایی خطر (از 0 تا 1)"""
        try:
            with open(file_path, "rb") as f: data = f.read()
            f_hash = hashlib.sha256(data).hexdigest()

            # ۱. چک کردن حافظه (اگه قبلاً اسکن شده)
            if f_hash in self.trust_db["hashes"]:
                return self.trust_db["hashes"][f_hash]

            # ۲. بررسی امضای واقعی ویندوز (سفید کردن خودکار)
            if self.verify_signature(file_path):
                self.trust_db["hashes"][f_hash] = 0.0
                self.save_trust_db()
                return 0.0

            # ۳. تحلیل با هوش مصنوعی
            features = self.get_file_features(data=data)
            if not features or not self.model: return 0.5
            
            f_vector = [features['entropy'], features['num_sections'], features['critical_api_count'], 
                        features['is_signed'], features['string_risk_score'], features['is_packed']]
            
            score = float(self.model.predict_proba([f_vector])[0][1])
            
            # یادگیری: اگه امتیاز خیلی پایین بود، به لیست امن‌ها اضافه کن
            if score < 0.1:
                self.trust_db["hashes"][f_hash] = round(score, 2)
                self.save_trust_db()

            return round(score, 2)
        except Exception as e:
            print(f"[!] Error during scan: {e}") # این خط بهت میگه چرا ارور میده
            return 0.5