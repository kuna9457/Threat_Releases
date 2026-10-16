from app.config import settings

def check_abuseipdb(url: str):
    if not settings.abuseipdb_api_key:
        return 0
    return 0

def check_urlscan(url: str):
    if not settings.urlscan_api_key:
        return {}
    return {}
