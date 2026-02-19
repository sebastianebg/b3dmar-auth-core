"""Preconfigured rate limiting for auth endpoints.

Wraps slowapi with sensible defaults for login, registration, and token refresh.
Each project can use these limiters directly or override the rates.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Default limiter keyed by client IP
limiter = Limiter(key_func=get_remote_address)

# Standard rate limit strings for auth endpoints
LOGIN_RATE = "5/minute"
REGISTER_RATE = "3/minute"
REFRESH_RATE = "10/minute"
PASSWORD_RESET_RATE = "3/minute"
