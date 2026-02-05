import hashlib

def get_file_hash(file_path):
    """محاسبه هش SHA256 برای شناسایی دقیق فایل"""
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return None

def is_whitelisted(file_hash):
    """چک کردن اینکه آیا فایل در لیست سفید دستی ما هست یا نه"""
    # این لیست رو می‌تونی توی یک فایل txt ذخیره کنی
    whitelist = [
        "هش_فایل_سایفون_شما", 
        "هش_فایل_معتبر_دیگر"
    ]
    return file_hash in whitelist