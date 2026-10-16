import threading
import time
from collections import deque


class RateLimiter:
    """
    Thread-safe sliding-window rate limiter.

    Scan threads call .acquire() before hitting a rate-limited API; if the
    window is full, the calling thread blocks (sleeps) until a slot frees up
    instead of firing the request and risking a 429. This is what lets a
    100-URL batch stay under each vendor's real per-minute limit no matter
    how many URLs are being scanned concurrently — the limiter paces the
    calls, the batch size doesn't have to.
    """

    def __init__(self, max_calls: int, period_seconds: float = 60.0):
        self.max_calls = max(1, max_calls)
        self.period = period_seconds
        self._calls = deque()
        self._lock = threading.Lock()

    def acquire(self):
        while True:
            with self._lock:
                now = time.monotonic()
                while self._calls and now - self._calls[0] >= self.period:
                    self._calls.popleft()
                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return
                wait = self.period - (now - self._calls[0])
            time.sleep(max(wait, 0.05))
