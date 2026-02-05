import os
import sys
import base64
import random
import re
import math
import time
import hashlib
import datetime
import psutil
import json
import vt
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class MegaScanner:
    def __init__(self):
        self.quarantine_path = "quarantine_zone"
        if not os.path.exists(self.quarantine_path):
            os.makedirs(self.quarantine_path)
        
        # امضاهای رفتاری بدافزار (Heuristic Signatures)
        self.signatures = {
            "Network Access": r"(socket\.|requests\.|urllib|http\.client)",
            "System Manipulation": r"(os\.system|subprocess\.|winreg|chmod|rmdir|shutil)",
            "Code Injection/Obfuscation": r"(eval\(|exec\(|base64\.b64decode|marshal\.|pickle\.)",
            "Persistence/Startup": r"(Software\\Microsoft\\Windows\\CurrentVersion\\Run|Registry)",
            "Keylogging/Hooking": r"(pynput|keyboard\.hook|SetWindowsHookEx)"
        }
        self.observer = None
        self.signatures = self.load_database()

    def scan_running_processes(self):
        """اسکن تمام برنامه‌های در حال اجرا در حافظه RAM"""
        suspicious_procs = []
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                exe_path = proc.info['exe']
                if exe_path:
                    # استفاده از همان موتور اسکن فایل برای چک کردن فایل اجرایی برنامه
                    result = self.scan_file(exe_path)
                    if result['score'] > 0.6:
                        suspicious_procs.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'path': exe_path,
                            'score': result['score']
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return suspicious_procs

    def kill_process(self, pid):
        """بستن اجباری یک برنامه مخرب"""
        try:
            proc = psutil.Process(pid)
            proc.terminate() # یا proc.kill()
            return True
        except:
            return False
        
    def get_file_hash(self, file_path):
        """محاسبه اثر انگشت MD5 فایل"""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                # فایل رو تکه تکه می‌خونیم که سیستم در فایل‌های سنگین هنگ نکنه
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return None

    def check_signatures(self, file_hash):
        """چک کردن اثر انگشت در لیست ویروس‌های شناخته شده"""
        # این یک لیست نمونه است، در آینده این رو از فایل db.json می‌خونیم
        known_viruses = {
            "44d88612fea8a8f36de82e1278abb02f": "EICAR Test Virus",
            "5d41402abc4b2a76b9719d911017c592": "Sample Trojan",
        }
        return known_viruses.get(file_hash, None)
    
    def calculate_entropy(self, data):
        """محاسبه انتروپی برای تشخیص فایل‌های کدگذاری شده یا رمزنگاری شده مشکوک"""
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def scan_file(self, file_path):
        """آنالیز چندلایه: متادیتا، رشته‌ها و انتروپی"""
        try:
            file_hash = self.get_file_hash(file_path)
            virus_name = self.check_signatures(file_hash)
            score = 0.0
            findings = []
            file_name = os.path.basename(file_path).lower()

            if virus_name:
                return {
                    "status": "Malware",
                    "score": 1.0, # دقت ۱۰۰ درصد
                    "findings": [f"Known Virus: {virus_name}"],
                    "path": file_path
                }
            # ۱. بررسی حجم و پسوند
            if file_name.endswith(('.exe', '.bat', '.pyw', '.msi', '.vbs', '.ps1')):
                score += 0.2
                findings.append("Executable/Script Extension")

            # ۲. آنالیز محتوا (Deep String Inspection)
            try:
                with open(file_path, "r", errors="ignore") as f:
                    content = f.read()
                    for desc, pattern in self.signatures.items():
                        if re.search(pattern, content, re.IGNORECASE):
                            score += 0.25
                            findings.append(desc)
            except: pass

            # ۳. بررسی انتروپی (تشخیص Pack/Encrypt مشکوک)
            try:
                with open(file_path, "rb") as f:
                    raw_data = f.read(2048).decode('latin-1', errors='ignore')
                    entropy = self.calculate_entropy(raw_data)
                    if entropy > 7.0: # انتروپی بالا نشانه رمزنگاری یا فشرده‌سازی ویروس است
                        score += 0.3
                        findings.append("High Entropy (Suspected Obfuscation)")
            except: pass

            # ۴. بررسی کلمات کلیدی در اسم فایل
            if any(x in file_name for x in ["hack", "crack", "virus", "bypass", "payload"]):
                score += 0.2
                findings.append("Suspicious Filename")

            final_score = min(score, 1.0)
            status = "Malware" if final_score > 0.6 else "Suspicious" if final_score > 0.3 else "Clean"
            
            return {
                "status": status,
                "score": final_score,
                "findings": findings,
                "path": file_path
            }
        except Exception as e:
            return {"status": "Error", "score": 0.0, "findings": [str(e)], "path": file_path}

    def isolate_file(self, file_path):
        """انتقال فایل به قرنطینه و تغییر ساختار برای غیرفعال‌سازی"""
        try:
            name = os.path.basename(file_path)
            with open(file_path, "rb") as f:
                data = f.read()
            # وارونه کردن بیت‌ها + Base64 برای غیرفعال کردن فایل اجرایی
            locked_data = base64.b64encode(data[::-1])
            with open(os.path.join(self.quarantine_path, f"{name}.locked"), "wb") as f:
                f.write(locked_data)
            os.remove(file_path)
            return True
        except: return False

    def start_monitoring(self, path, callback):
        if self.observer: self.stop_monitoring()
        self.observer = Observer()
        handler = MonitorHandler(self, callback)
        self.observer.schedule(handler, path, recursive=False)
        self.observer.start()

    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
    
    def get_quarantine_files(self):
        """لیست کردن تمام فایل‌های موجود در قرنطینه"""
        if not os.path.exists(self.quarantine_path):
            return []
        return os.listdir(self.quarantine_path)

    def restore_file(self, locked_filename, original_dest_path):
        """بازگرداندن فایل از قرنطینه به حالت اول"""
        try:
            locked_path = os.path.join(self.quarantine_path, locked_filename)
            with open(locked_path, "rb") as f:
                encoded_data = f.read()
            
            # باز کردن رمزنگاری (برعکس کردن پروسه ایزولاسیون)
            decoded_data = base64.b64decode(encoded_data)[::-1]
            
            with open(original_dest_path, "wb") as f:
                f.write(decoded_data)
            
            os.remove(locked_path)
            return True
        except Exception as e:
            print(f"Restore Error: {e}")
            return False
        
    def get_network_connections(self):
        """لیست کردن تمام برنامه‌هایی که در حال استفاده از اینترنت هستند"""
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED': # فقط ارتباطات برقرار شده
                try:
                    proc = psutil.Process(conn.pid)
                    connections.append({
                        'pid': conn.pid,
                        'name': proc.name(),
                        'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote': f"{conn.raddr.ip}:{conn.raddr.port}"
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        return connections
    
    def protect_me():
        """بالا بردن اولویت برنامه در سیستم عامل برای جلوگیری از بسته شدن توسط بدافزار"""
        try:
            if os.name == 'nt': # مخصوص ویندوز
                import win32api, win32process, win32con
                pid = win32api.GetCurrentProcessId()
                handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, pid)
                # تعیین وضعیت HIGH_PRIORITY_CLASS
                win32process.SetPriorityClass(handle, win32process.HIGH_PRIORITY_CLASS)
        except:
            pass
    
    def load_database(self):
        """بارگذاری دیتابیس بزرگ ویروس‌ها"""
        db_path = "database/db.json"
        if os.path.exists(db_path):
            with open(db_path, "r") as f:
                data = json.load(f)
                return data.get("virus_signatures", {})
        return {}
    # در کلاس MegaScanner یا یک کلاس جدید:
    def get_ai_verdict(self, file_res, proc_res, net_res):
        """
        این تابع داده‌های خام رو میگیره و مثل یک قاضی هوشمند نظر میده.
        """
        risk_score = (file_res['score'] * 0.5) + (len(proc_res) * 0.3) + (len(net_res) * 0.2)
    
        if risk_score > 0.8:
            return "🔴 بحرانی: این سیستم تحت حمله است. توصیه: قطع فوری اینترنت و پاکسازی پردازش‌ها."
        elif risk_score > 0.4:
            return "🟡 اخطار: فعالیت‌های مشکوک شناسایی شد. سیستم را مانیتور کنید."
        else:
            return "🟢 ایمن: تمام پارامترها نرمال هستند."
        # در کلاس MegaScanner یا یک کلاس جدید:
     
    def check_virustotal(self, file_hash):
        """چک کردن وضعیت فایل در ۷۰ آنتی‌ویروس جهانی"""
        # باید از سایت VirusTotal یک API Key رایگان بگیری
        api_key = "YOUR_API_KEY_HERE" 
        try:
            with vt.Client(api_key) as client:
                file_obj = client.get_object(f"/files/{file_hash}")
                stats = file_obj.last_analysis_stats
                # برگرداندن تعداد آنتی‌ویروس‌هایی که گفتن این فایل ویروسه
                return stats['malicious']
        except Exception:
            return 0
    
    def deep_scan_online(self, file_path):
        file_hash = self.get_file_hash(file_path)
        api_key = "a0dd26d83c78c048de46a60c88f953bd0870793a3f1a128ea8bca90b8796d77a"
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key}
        proxies = {
        "http": "http://10.1.19.2:8080",
        "https": "http://10.1.19.2:8080",
    }
        try:
            response = requests.get(url, headers=headers, proxies=proxies, timeout=20)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious_count = stats['malicious']
            
            # ارسال نتایج به هوش مصنوعی برای "یادگیری"
                self.ai_learn(file_path, malicious_count, data['data']['attributes']['last_analysis_results'])
            
                return malicious_count
            else:
                return "عدم وجود فایل در دیتابیس جهانی"
        except Exception as e:
            return f"Error: {str(e)}"
        
    def ai_learn(self, file_path, malicious_count, detailed_results):
        """ذخیره تجربه برای یادگیری هوش مصنوعی در آینده"""
        with open("database/ai_learning_logs.json", "a") as f:
            log = {
                "file": file_path,
                "danger_level": malicious_count,
                "is_virus": malicious_count > 5,
                "timestamp": str(datetime.datetime.now())
            }
            f.write(json.dumps(log) + "\n")
def generate_report(self, scan_results, system_status):
    report_name = f"Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_name, "w", encoding="utf-8") as f:
        f.write("🛡️ MEGAGUARD SECURITY REPORT\n")
        f.write("============================\n")
        f.write(f"تاریخ اسکن: {datetime.datetime.now()}\n")
        f.write(f"وضعیت نهایی سیستم: {system_status}\n\n")
        f.write("🔍 نتایج اسکن فایل‌ها:\n")
        for res in scan_results:
            f.write(f"- {res['path']} -> {res['status']} (Score: {res['score']})\n")
        f.write("\n✅ مگاگارد آماده محافظت از شماست.")
    return report_name
        
def get_ai_verdict(self, file_res, proc_res, net_res):
    """
    این تابع داده‌های خام رو میگیره و مثل یک قاضی هوشمند نظر میده.
    """
    risk_score = (file_res['score'] * 0.5) + (len(proc_res) * 0.3) + (len(net_res) * 0.2)
    
    if risk_score > 0.8:
        return "🔴 بحرانی: این سیستم تحت حمله است. توصیه: قطع فوری اینترنت و پاکسازی پردازش‌ها."
    elif risk_score > 0.4:
        return "🟡 اخطار: فعالیت‌های مشکوک شناسایی شد. سیستم را مانیتور کنید."
    else:
        return "🟢 ایمن: تمام پارامترها نرمال هستند."  

class MonitorHandler(FileSystemEventHandler):
    def __init__(self, scanner_instance, callback):
        self.scanner = scanner_instance
        self.callback = callback
    def on_created(self, event):
        if not event.is_directory:
            time.sleep(0.7) # صبر برای اتمام نوشته شدن فایل روی هارد
            result = self.scanner.scan_file(event.src_path)
            self.callback(result)

class SecurityOrchestrator:
    def __init__(self, scanner):
        self.scanner = scanner

    def analyze_system_health(self):
        """جمع‌بندی تمام لایه‌ها برای صدور حکم نهایی"""
        threat_level = 0
        reasons = []

        # چک کردن پروسه‌ها
        procs = self.scanner.scan_running_processes()
        if procs:
            threat_level += 40
            reasons.append(f"Found {len(procs)} suspicious processes")

        # چک کردن شبکه
        conns = self.scanner.get_network_connections()
        for c in conns:
            if "4444" in c['remote'] or "8888" in c['remote']: # پورت‌های معروف هکری
                threat_level += 30
                reasons.append("Suspicious C2 port detected")

        return {
            "danger_score": min(threat_level, 100),
            "verdict": "CRITICAL" if threat_level > 70 else "WARNING" if threat_level > 30 else "SAFE",
            "details": reasons
        }