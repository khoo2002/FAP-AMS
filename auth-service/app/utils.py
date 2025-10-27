import time
from collections import defaultdict, deque
from typing import Tuple


class SimpleRateLimiter:
    """Naive in-memory sliding window limiter (per key). Not suitable for multi-instance.
    window_seconds: window length; max_events: allowed events per window.
    """
    def __init__(self, window_seconds: int = 60, max_events: int = 10):
        self.window = window_seconds
        self.max = max_events
        self.events = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.time()
        q = self.events[key]
        # prune old
        while q and (now - q[0]) > self.window:
            q.popleft()
        if len(q) >= self.max:
            return False
        q.append(now)
        return True


def get_client_ip(request) -> str:
    xfwd = request.headers.get('x-forwarded-for')
    if xfwd:
        return xfwd.split(',')[0].strip()
    return request.client.host if request.client else ''
