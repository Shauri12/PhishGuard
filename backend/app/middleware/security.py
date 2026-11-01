"""
PhishGuard — Security Middleware & Rate Limiter
================================================
Provides:
  - Per-IP rate limiting (100 req / 60s window) via a sliding-window counter
  - Request size guard (max 8KB body)
  - Security response headers (CSP, X-Frame-Options, etc.)
  - Input sanitisation helper
"""

import time
import re
from collections import defaultdict
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# ── Config ────────────────────────────────────────────────────
RATE_LIMIT_REQUESTS  = 100    # max requests per window
RATE_LIMIT_WINDOW    = 60     # sliding window in seconds
MAX_BODY_BYTES       = 8_192  # 8 KB


# ── Sliding-window per-IP counter ─────────────────────────────
_windows: dict[str, list] = defaultdict(list)


def _is_rate_limited(ip: str) -> bool:
    now   = time.time()
    hits  = _windows[ip]
    # Drop entries outside the window
    _windows[ip] = [t for t in hits if now - t < RATE_LIMIT_WINDOW]
    if len(_windows[ip]) >= RATE_LIMIT_REQUESTS:
        return True
    _windows[ip].append(now)
    return False


# ── Security Middleware ───────────────────────────────────────
class SecurityMiddleware(BaseHTTPMiddleware):
    """Attaches security headers and enforces rate limiting / body size."""

    SECURITY_HEADERS = {
        "X-Content-Type-Options":    "nosniff",
        "X-Frame-Options":           "DENY",
        "X-XSS-Protection":          "1; mode=block",
        "Referrer-Policy":           "strict-origin-when-cross-origin",
        "Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
        "Cache-Control":             "no-store",
        # Relaxed CSP — still allows browser extension and React dashboard
        "Content-Security-Policy":   "default-src 'self'; connect-src *; frame-ancestors 'none'",
    }

    async def dispatch(self, request: Request, call_next):
        # 1. Rate limiting
        client_ip = request.client.host if request.client else "unknown"
        if _is_rate_limited(client_ip):
            return JSONResponse(
                status_code=429,
                content={
                    "error":   "Too Many Requests",
                    "detail":  f"Rate limit exceeded: {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW}s.",
                    "retry_after": RATE_LIMIT_WINDOW,
                },
                headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
            )

        # 2. Body size guard (only for POST / PUT)
        if request.method in ("POST", "PUT", "PATCH"):
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > MAX_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"error": "Request body too large", "max_bytes": MAX_BODY_BYTES},
                )

        response: Response = await call_next(request)

        # 3. Attach security headers
        for k, v in self.SECURITY_HEADERS.items():
            response.headers[k] = v

        return response


# ── Input Sanitisation Helpers ────────────────────────────────
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MAX_URL_LEN   = 2048


def sanitize_url(raw: str) -> str:
    """Strip control characters and truncate oversized URLs."""
    url = _CONTROL_CHARS.sub("", raw).strip()
    if len(url) > _MAX_URL_LEN:
        url = url[:_MAX_URL_LEN]
    return url

