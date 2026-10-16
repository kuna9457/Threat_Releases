import requests
from app.config import settings

def check_google_safe(url: str):
    if not settings.google_safe_browsing_api_key:
        if "phish" in url.lower():
            return True
        return False
        
    # Standard Google Safe Browsing API check would go here
    return False
