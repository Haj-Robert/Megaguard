import wmi
import threading

class USBGuard:
    def __init__(self, scan_callback):
        self.scan_callback = scan_callback
        self.c = wmi.WMI()

    def start_monitoring(self):
        """گوش دادن به رویدادهای ورود سخت‌افزار جدید"""
        # ایجاد واچر برای درایوهای جدید
        watcher = self.c.watch_for(
            notification_type="Creation",
            wmi_class="Win32_LogicalDisk"
        )
        
        def listen():
            while True:
                try:
                    usb_drive = watcher()
                    # اگه نوع درایو ۲ باشه یعنی Removable (مثل فلش)
                    if usb_drive.DriveType == 2:
                        drive_letter = usb_drive.Caption # مثلا :E
                        self.scan_callback(drive_letter)
                except:
                    pass

        threading.Thread(target=listen, daemon=True).start()