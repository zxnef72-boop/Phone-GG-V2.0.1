"""
Gravatar lookup — ambil URL foto profil dari email.
"""
import hashlib
import requests


def get_gravatar(email: str, size: int = 200) -> str | None:
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{email_hash}?d=404&s={size}"
    try:
        resp = requests.head(url, timeout=5)
        return url if resp.status_code == 200 else None
    except requests.RequestException:
        return None
