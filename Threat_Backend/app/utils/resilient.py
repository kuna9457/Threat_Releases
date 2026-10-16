"""Shared 'never give up, never fake a result' helpers for every external lookup.

When an API is rate limited, a server errors, or the internet/proxy connection drops,
the calling thread PAUSES (with a visible message) and retries until the call really
succeeds, instead of returning an error/empty result that would end up in the report.
"""
import threading
import time

import requests

try:
    from app.utils.ssl_patch import apply_ssl_patch
    apply_ssl_patch()
except Exception:
    pass

_print_lock = threading.Lock()


def _say(msg: str):
    with _print_lock:
        print(msg, flush=True)


def internet_ok() -> bool:
    """True if any HTTPS endpoint answers (any HTTP status counts). Uses the system proxy settings."""
    for u in ("https://www.virustotal.com", "https://www.google.com", "https://urlscan.io"):
        try:
            requests.head(u, timeout=8, allow_redirects=False)
            return True
        except Exception:
            continue
    return False


def pause(source: str, reason: str, attempt: int, base: float = 15, cap: float = 300, override: float | None = None):
    wait = override if override else min(cap, base * (2 ** min(attempt - 1, 5)))
    _say(f"[PAUSED] {source}: {reason}. Waiting {wait:.0f}s, then retrying (attempt {attempt}) ...")
    end = time.monotonic() + wait
    next_note = time.monotonic() + 300
    while True:
        left = end - time.monotonic()
        if left <= 0:
            return
        time.sleep(min(30, left))
        if time.monotonic() >= next_note and end - time.monotonic() > 0:
            _say(f"[PAUSED] {source}: still waiting - about {max(0, (end - time.monotonic()) / 60):.0f} min left")
            next_note = time.monotonic() + 300


def wait_for_internet(source: str):
    """Block until the internet/proxy connection is back."""
    n = 0
    while not internet_ok():
        n += 1
        pause(source, "No internet / proxy connection", n, base=10, cap=60)
    if n:
        _say(f"[RESUMED] {source}: connection restored")


def resilient_get(source: str, limiter, url: str, *, headers=None, params=None, timeout=20, auth_retries=3,
                  max_wait=None):
    """requests.get that pauses + retries on connection errors, 429 and 5xx.
    401/403 (bad key / quota) are retried `auth_retries` times, then returned to the caller."""
    attempt = 0
    auth = 0
    while True:
        if limiter is not None:
            limiter.acquire()
        try:
            r = requests.get(url, headers=headers, params=params, timeout=timeout)
        except requests.RequestException as e:
            attempt += 1
            wait_for_internet(source)
            pause(source, f"connection problem ({type(e).__name__})", attempt, base=10)
            continue
        sc = r.status_code
        if sc == 429:
            attempt += 1
            ra = r.headers.get("Retry-After", "")
            wait = int(ra) + 2 if ra.isdigit() else None
            if max_wait is not None and wait is not None and wait > max_wait:
                # optional source with a long (e.g. daily) quota wait: hand the 429 back instead of freezing the run
                _say(f"[SKIPPED] {source}: quota exhausted (resets in ~{wait // 3600}h) - not used for the risk result")
                return r
            pause(source, "API rate limit reached (429)", attempt, base=60, cap=300, override=wait)
            continue
        if sc >= 500:
            attempt += 1
            pause(source, f"server error {sc}", attempt)
            continue
        if sc in (401, 403) and auth < auth_retries:
            auth += 1
            pause(source, f"auth/quota error {sc}", auth, base=30)
            continue
        return r


def is_transient_error(text: str) -> bool:
    t = (text or "").lower()
    return any(k in t for k in ("429", "rate limit", "timeout", "timed out", "connection", "reset",
                                 "refused", "temporar", "http 5", "unreachable", "max retries"))
