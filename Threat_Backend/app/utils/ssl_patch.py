"""
ssl_patch.py — Universal SSL/TLS bypass and certificate handling for corporate proxies (Zscaler, BlueCoat, etc.)

Fixes SSL verification failures that occur in corporate environments where outbound HTTPS
traffic is intercepted by a corporate MITM proxy (e.g. Zscaler) using internal enterprise CAs
not present in Python's bundled certifi CA bundle.
"""

import os
import sys
import ssl
import warnings

def apply_ssl_patch():
    # 1. Environment variables
    os.environ["PYTHONHTTPSVERIFY"] = "0"
    os.environ.pop("REQUESTS_CA_BUNDLE", None)
    os.environ.pop("CURL_CA_BUNDLE", None)
    os.environ.pop("SSL_CERT_FILE", None)

    # 2. Suppress InsecureRequestWarning and urllib3 warnings
    warnings.filterwarnings("ignore")
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        urllib3.disable_warnings()
    except Exception:
        pass

    # 3. Patch standard library ssl to allow unverified HTTPS by default
    try:
        ssl._create_default_https_context = ssl._create_unverified_context
    except Exception:
        pass

    # 4. Patch requests HTTPAdapter.send so all requests (VT, URLScan, SSL Labs, etc.) skip verify
    try:
        import requests
        from requests import adapters as _ra

        _orig_send = _ra.HTTPAdapter.send
        def _unverified_send(self, req, **kwargs):
            kwargs["verify"] = False
            return _orig_send(self, req, **kwargs)

        _ra.HTTPAdapter.send = _unverified_send

        # Also patch Session.request just in case
        _orig_session_req = requests.Session.request
        def _unverified_session_req(self, method, url, **kwargs):
            if "verify" not in kwargs or kwargs["verify"] is True:
                kwargs["verify"] = False
            return _orig_session_req(self, method, url, **kwargs)

        requests.Session.request = _unverified_session_req
    except Exception as e:
        print(f"[WARN] Could not patch requests: {e}")

    # 5. Patch urllib.request to default to unverified SSL context
    try:
        import urllib.request
        _orig_urlopen = urllib.request.urlopen

        def _unverified_urlopen(url, *args, **kwargs):
            if "context" not in kwargs or kwargs["context"] is None:
                try:
                    kwargs["context"] = ssl._create_unverified_context()
                except Exception:
                    pass
            return _orig_urlopen(url, *args, **kwargs)

        urllib.request.urlopen = _unverified_urlopen
    except Exception:
        pass

# Automatically run on import
apply_ssl_patch()
