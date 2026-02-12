import wmi
import threading
import os

class USBGuard:
    # با اضافه کردن *args و **kwargs، پایتون دیگه نمیتونه بخاطر تعداد ورودی ارور بده
    def __init__(self, scanner_instance, log_callback, *args, **kwargs):
        self.scanner = scanner_instance
        self.log_callback = log_callback
        try:
            self.c = wmi.WMI()
        except Exception as e:
            print(f"WMI Error: {e}")

    def start(self):
        def monitor():
            try:
                # مانیتورینگ تغییرات درایوها
                watcher = self.c.watch_for(
                    notification_type="Creation",
                    wmi_class="Win32_LogicalDisk"
                )
                self.log_callback("[🛡️] نگهبان USB با موفقیت فعال شد.")
                while True:
                    usb_drive = watcher()
                    if usb_drive.DriveType == 2:
                        self.process_new_usb(usb_drive.Caption)
            except Exception as e:
                self.log_callback(f"[❌] خطای نگهبان: {str(e)}")

        threading.Thread(target=monitor, daemon=True).start()

    def process_new_usb(self, drive_path):
        self.log_callback(f"\n[⚠️] فلش مموری وصل شد: {drive_path}")
        self.scanner.scan_directory(drive_path)