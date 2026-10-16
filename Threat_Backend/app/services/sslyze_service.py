"""
SSLyze Integration Service
Runs a real, local SSLyze scan (no external API) against the target's
port 443 to find every TLS/SSL protocol version the server still accepts.
The weakest protocol still accepted is what the risk engine cares about —
a server can offer TLS 1.3 while still allowing downgrade to something
much older, which is the real exposure.
"""

from urllib.parse import urlparse

from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommand,
    ServerScanStatusEnum,
    ScanCommandAttemptStatusEnum,
)
from sslyze.errors import ServerHostnameCouldNotBeResolved

_PROTOCOL_SCAN_COMMANDS = {
    ScanCommand.SSL_2_0_CIPHER_SUITES: "SSL 2.0",
    ScanCommand.SSL_3_0_CIPHER_SUITES: "SSL 3.0",
    ScanCommand.TLS_1_0_CIPHER_SUITES: "TLS 1.0",
    ScanCommand.TLS_1_1_CIPHER_SUITES: "TLS 1.1",
    ScanCommand.TLS_1_2_CIPHER_SUITES: "TLS 1.2",
    ScanCommand.TLS_1_3_CIPHER_SUITES: "TLS 1.3",
}

_RESULT_FIELD_BY_COMMAND = {
    ScanCommand.SSL_2_0_CIPHER_SUITES: "ssl_2_0_cipher_suites",
    ScanCommand.SSL_3_0_CIPHER_SUITES: "ssl_3_0_cipher_suites",
    ScanCommand.TLS_1_0_CIPHER_SUITES: "tls_1_0_cipher_suites",
    ScanCommand.TLS_1_1_CIPHER_SUITES: "tls_1_1_cipher_suites",
    ScanCommand.TLS_1_2_CIPHER_SUITES: "tls_1_2_cipher_suites",
    ScanCommand.TLS_1_3_CIPHER_SUITES: "tls_1_3_cipher_suites",
}


def _extract_host(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return urlparse(url).netloc.split(":")[0]


def check_sslyze(url: str, port: int = 443) -> dict:
    """Runs the scan; connection-type failures are re-tried (pausing while the internet is down)."""
    from app.utils.resilient import wait_for_internet, pause
    result = {}
    for attempt in range(1, 4):
        result = _check_sslyze_once(url, port)
        err = result.get("error") or ""
        if not err or "Invalid URL" in err:
            return result
        wait_for_internet("SSLyze")   # blocks while offline; returns at once if the net is fine
        if "Could not resolve hostname" in err:
            return _check_sslyze_once(url, port)   # net is up -> the host really does not resolve
        if attempt < 3:
            pause("SSLyze", f"scan error ({err[:80]})", attempt, base=5, cap=20)
    return result


def _check_sslyze_once(url: str, port: int = 443) -> dict:
    """
    Returns {"host", "port", "protocols": [{"name","version"}...], "error": str|None}
    for every TLS/SSL protocol version SSLyze found the server still accepts.
    An empty "protocols" list with no error means the connection succeeded
    but nothing recognisable was negotiated (should be rare).
    """
    host = _extract_host(url)
    if not host:
        return {"error": "Invalid URL — could not extract host"}

    try:
        location = ServerNetworkLocation(hostname=host, port=port)
        request = ServerScanRequest(
            server_location=location,
            scan_commands=set(_PROTOCOL_SCAN_COMMANDS.keys()),
        )
    except ServerHostnameCouldNotBeResolved:
        return {"error": f"Could not resolve hostname: {host}"}
    except Exception as e:
        return {"error": f"SSLyze setup error: {e}"}

    try:
        scanner = Scanner(per_server_concurrent_connections_limit=4, concurrent_server_scans_limit=1)
        scanner.queue_scans([request])

        for result in scanner.get_results():
            if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
                return {"error": f"Could not connect to {host}:{port} — {result.connectivity_error_trace}"}

            protocols = []
            for command, label in _PROTOCOL_SCAN_COMMANDS.items():
                field = _RESULT_FIELD_BY_COMMAND[command]
                attempt = getattr(result.scan_result, field)

                if attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
                    continue  # that one protocol probe failed — skip it, don't fail the whole scan

                accepted = attempt.result.accepted_cipher_suites
                if accepted:
                    name, version = label.split(" ", 1)
                    protocols.append({"name": name, "version": version})

            return {"host": host, "port": port, "protocols": protocols, "error": None}

        return {"error": "SSLyze returned no scan result"}

    except Exception as e:
        return {"error": f"SSLyze integration error: {e}"}
