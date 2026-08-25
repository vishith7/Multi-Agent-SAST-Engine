import time

class RateLimiter:
    def __init__(self, requests_per_minute_limit=25):
        self.requests_per_minute = requests_per_minute_limit
        self.request_timestamps = []

    def wait_if_needed(self):
        """
        Blocks until a request can be safely made according to the RPM limit.
        """
        if self.requests_per_minute <= 0 or self.requests_per_minute == float('inf'):
            return

        now = time.time()
        
        # Remove timestamps older than 60 seconds
        self.request_timestamps = [ts for ts in self.request_timestamps if now - ts < 60.0]
        
        if len(self.request_timestamps) >= self.requests_per_minute:
            # We hit the limit. Wait until the oldest request in the window expires.
            oldest = self.request_timestamps[0]
            sleep_time = 60.0 - (now - oldest)
            if sleep_time > 0:
                time.sleep(sleep_time)
                
            # After sleeping, refresh the window
            now = time.time()
            self.request_timestamps = [ts for ts in self.request_timestamps if now - ts < 60.0]

        # Record the current request
        self.request_timestamps.append(time.time())

# Global singleton
_limiter = None

def get_rate_limiter(rpm=25):
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter(requests_per_minute_limit=rpm)
    else:
        # Update rpm limit if it changed
        _limiter.requests_per_minute = rpm
    return _limiter
