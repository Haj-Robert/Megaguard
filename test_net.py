import socket

def check_socket():
    try:
        # تست مستقیم پورت ۸۰ گوگل بدون پروتکل HTTPS
        host = socket.gethostbyname("www.google.com")
        s = socket.create_connection((host, 80), 2)
        print("✅ اتصال سوکت برقرار شد! مشکل کد نیست، مشکل دسترسیه.")
        s.close()
    except Exception as e:
        print(f"❌ حتی سوکت هم بسته است: {e}")

check_socket()