from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    virustotal_api_key: Optional[str] = None
    google_safe_browsing_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    urlscan_api_key: Optional[str] = None
    urlhaus_api_key: Optional[str] = None

    # Per-vendor rate limits (requests/minute). Defaults match each vendor's
    # public/free-tier ceiling — raise these in .env if you're on a paid plan.
    # VirusTotal public API is hard-capped at 4/min regardless of what's set here.
    virustotal_rpm: int = 4
    abuseipdb_rpm: int = 30
    urlscan_rpm: int = 30
    # SSL Labs isn't a per-minute quota — it's a "don't run too many
    # simultaneous fresh assessments" ask. This caps concurrent requests, not rate.
    ssl_labs_max_concurrent: int = 4

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
